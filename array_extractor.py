# Array Extractor - IDA Pro plugin


import struct
from collections import namedtuple, OrderedDict

# IDA availability guard - lets this file be imported/unit-tested stand-alone
try:
    import ida_idaapi
    import ida_kernwin
    import ida_bytes
    import idaapi
    import idc
    IN_IDA = True
except ImportError:
    IN_IDA = False

PLUGIN_NAME = "Array Extractor"
PLUGIN_HOTKEY = "Ctrl-Alt-A"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "Seif"


# 1. Supported element ("data") types

TypeInfo = namedtuple("TypeInfo", ["label", "struct_fmt", "size", "kind"])
# kind is "num" (fixed-size numeric) or "str" (null-terminated C string)

TYPES = OrderedDict([
    ("int8",   TypeInfo("Int8 (signed byte)",        "b", 1, "num")),
    ("uint8",  TypeInfo("UInt8 (unsigned byte)",      "B", 1, "num")),
    ("int16",  TypeInfo("Int16",                      "h", 2, "num")),
    ("uint16", TypeInfo("UInt16",                     "H", 2, "num")),
    ("int32",  TypeInfo("Int32",                      "i", 4, "num")),
    ("uint32", TypeInfo("UInt32",                     "I", 4, "num")),
    ("int64",  TypeInfo("Int64",                      "q", 8, "num")),
    ("uint64", TypeInfo("UInt64",                     "Q", 8, "num")),
    ("float",  TypeInfo("Float32",                    "f", 4, "num")),
    ("double", TypeInfo("Float64",                    "d", 8, "num")),
    ("cstr",   TypeInfo("C string (null-terminated)", None, 0, "str")),
])
TYPE_KEYS = list(TYPES.keys())


# 2. Supported output languages - the 5 most commonly needed

LANGS = OrderedDict([
    ("python",     "Python"),
    ("c",          "C / C++"),
    ("csharp",     "C#"),
    ("java",       "Java"),
    ("javascript", "JavaScript (TypedArray)"),
])
LANG_KEYS = list(LANGS.keys())

# Bracket style used to build array literals.
LANG_SYNTAX = {
    "python":     ("[", "]"),
    "c":          ("{", "}"),
    "csharp":     ("{", "}"),
    "java":       ("{", "}"),
    "javascript": ("[", "]"),
}

# type_key -> language-native type name
CTYPE = {
    "c": {
        "int8": "int8_t", "uint8": "uint8_t", "int16": "int16_t", "uint16": "uint16_t",
        "int32": "int32_t", "uint32": "uint32_t", "int64": "int64_t", "uint64": "uint64_t",
        "float": "float", "double": "double", "cstr": "char*",
    },
    "csharp": {
        "int8": "sbyte", "uint8": "byte", "int16": "short", "uint16": "ushort",
        "int32": "int", "uint32": "uint", "int64": "long", "uint64": "ulong",
        "float": "float", "double": "double", "cstr": "string",
    },
    "java": {
        "int8": "byte", "uint8": "int", "int16": "short", "uint16": "int",
        "int32": "int", "uint32": "long", "int64": "long", "uint64": "long",
        "float": "float", "double": "double", "cstr": "String",
    },
    "javascript": {
        "int8": "Int8Array", "uint8": "Uint8Array", "int16": "Int16Array", "uint16": "Uint16Array",
        "int32": "Int32Array", "uint32": "Uint32Array", "int64": "BigInt64Array", "uint64": "BigUint64Array",
        "float": "Float32Array", "double": "Float64Array", "cstr": "Array",
    },
}

# Declaration templates.
LANG_DECL = {
    "python":     "{varname} = {body}\n",
    "c":          "{ctype} {varname}[{count}] = {body};\n",
    "csharp":     "{ctype}[] {varname} = new {ctype}[] {body};\n",
    "java":       "{ctype}[] {varname} = {body};\n",
    "javascript": "const {varname} = new {ctype}({body});\n",
}

COMMENT_CHAR = {lang: ("#" if lang == "python" else "//") for lang in LANG_KEYS}

ELEMENTS_PER_LINE = 8


# 3. Parsing: raw bytes -> Python values

def parse_values(data, type_key, big_endian, start_ea):
    if type_key == "cstr":
        values, addresses = [], []
        cur = start_ea
        buf = bytearray()
        for b in data:
            if b == 0:
                if buf:
                    values.append(buf.decode("utf-8", errors="replace"))
                    addresses.append(cur - len(buf))
                buf = bytearray()
            else:
                buf.append(b)
            cur += 1
        if buf:
            values.append(buf.decode("utf-8", errors="replace"))
            addresses.append(cur - len(buf))
        return values, "str", addresses

    ti = TYPES[type_key]
    endian = ">" if big_endian else "<"
    count = len(data) // ti.size
    if count == 0:
        return [], "num", []
    fmt = "{}{}{}".format(endian, count, ti.struct_fmt)
    values = list(struct.unpack(fmt, data[:count * ti.size]))
    addresses = [start_ea + i * ti.size for i in range(count)]
    return values, "num", addresses


# 4. Rendering helpers

def render_scalar(value, kind, use_hex, suffix=""):
    if kind == "str":
        escaped = (value.replace("\\", "\\\\")
                        .replace('"', '\\"')
                        .replace("\n", "\\n")
                        .replace("\t", "\\t"))
        return '"{}"'.format(escaped)
    if isinstance(value, float):
        return repr(value)
    if use_hex:
        text = "0x{:X}".format(value) if value >= 0 else "-0x{:X}".format(-value)
    else:
        text = str(value)
    return text + suffix


def build_flat_body(values, kind, lang, use_hex, per_line, suffix=""):
    o, c = LANG_SYNTAX[lang]
    indent = "    "
    per_line = max(1, int(per_line or 8))
    items = [render_scalar(v, kind, use_hex, suffix) for v in values]
    if not items:
        return o + c
    rows = []
    for i in range(0, len(items), per_line):
        row_items = items[i:i + per_line]
        rows.append(indent + ", ".join(row_items) + ",")
    return o + "\n" + "\n".join(rows) + "\n" + c


def format_output(lang, values, kind, addresses, var_name, type_key, per_line, use_hex):
    ctype = CTYPE.get(lang, {}).get(type_key, "auto")
    count = len(values)
    suffix = "n" if (lang == "javascript" and type_key in ("int64", "uint64")) else ""

    body = build_flat_body(values, kind, lang, use_hex, per_line, suffix)
    if lang == "javascript" and kind == "str":
        return "const {} = {};\n".format(var_name, body)
    template = LANG_DECL[lang]
    return template.format(
        varname=var_name, VARNAME=var_name.upper(), ctype=ctype,
        count=count, body=body,
    )


def build_header(lang, start_ea, end_ea, type_key, item_count):
    comment = COMMENT_CHAR[lang]
    ti = TYPES[type_key]
    lines = [
        "Extracted with {} v{}".format(PLUGIN_NAME, PLUGIN_VERSION),
        "Range : 0x{:X} - 0x{:X}  ({} bytes)".format(start_ea, end_ea, end_ea - start_ea),
        "Type  : {}   Count: {}".format(ti.label, item_count),
    ]
    return "\n".join("{} {}".format(comment, line) for line in lines) + "\n\n"


# 5. IDA GLUE - everything below actually touches idaapi

if IN_IDA:

    ACTION_ID = "array_extractor:run"

    def get_endianness():
        try:
            import ida_ida
            return bool(ida_ida.inf_is_be())
        except Exception:
            pass
        try:
            return bool(idaapi.cvar.inf.is_be())
        except Exception:
            pass
        try:
            return bool(idaapi.cvar.inf.mf)
        except Exception:
            return False

    def read_bytes_range(start_ea, end_ea):
        size = end_ea - start_ea
        if size <= 0:
            return None
        return ida_bytes.get_bytes(start_ea, size)

    def get_current_selection():
        try:
            view = ida_kernwin.get_current_viewer()
            ok, sel_start, sel_end = ida_kernwin.read_range_selection(view)
            if ok and sel_end > sel_start:
                # Make sure the *whole* last selected item is included,
                # in case the selection end lands on its first byte only.
                try:
                    last_item_end = idc.get_item_end(sel_end - 1)
                    if last_item_end > sel_end:
                        sel_end = last_item_end
                except Exception:
                    pass
                return sel_start, sel_end
        except Exception:
            pass
        return None, None

    def copy_to_clipboard(text):
        try:
            try:
                from PyQt5.QtWidgets import QApplication
            except ImportError:
                try:
                    from PySide2.QtWidgets import QApplication
                except ImportError:
                    from PySide6.QtWidgets import QApplication  # noqa: F401
            app = QApplication.instance()
            if app is None:
                return False
            app.clipboard().setText(text)
            return True
        except Exception:
            return False

    # ---------------------------------------------------------------- Forms

    class ExtractorForm(ida_kernwin.Form):
        def __init__(self):
            F = ida_kernwin.Form
            type_items = [t.label for t in TYPES.values()]
            lang_items = list(LANGS.values())
            F.__init__(self, r"""STARTITEM 0
BUTTON YES* Extract
BUTTON CANCEL Cancel
Array Extractor  (by Seif)
{FormChangeCb}
<Data type:{cType}>
<Output language:{cLang}>
<List / array name:{sVarName}>
<Number format:{cNumFormat}>
""", {
                "cType": F.DropdownListControl(items=type_items, readonly=True, selval=1),
                "cLang": F.DropdownListControl(items=lang_items, readonly=True, selval=0),
                "sVarName": F.StringInput(value="data"),
                "cNumFormat": F.DropdownListControl(
                    items=["Hexadecimal", "Decimal"], readonly=True, selval=0
                ),
                "FormChangeCb": F.FormChangeCb(self.OnFormChange),
            })
            self.Compile()

        def OnFormChange(self, fid):
            return 1

    class ResultForm(ida_kernwin.Form):
        def __init__(self, text):
            F = ida_kernwin.Form
            F.__init__(self, r"""STARTITEM 0
BUTTON YES* Copy to Clipboard
BUTTON CANCEL Close
Array Extractor - Result
{FormChangeCb}
{tOutput}
""", {
                "tOutput": F.MultiLineTextControl(
                    text=text,
                    flags=F.MultiLineTextControl.TXTF_FIXEDFONT,
                ),
                "FormChangeCb": F.FormChangeCb(self.OnFormChange),
            })
            self.Compile()

        def OnFormChange(self, fid):
            return 1

    # ------------------------------------------------------------- Runner

    def run_extractor():
        start_ea, end_ea = get_current_selection()
        if start_ea is None or end_ea is None or end_ea <= start_ea:
            ida_kernwin.warning(
                "No range is selected.\n\n"
                "In the Disassembly or Hex view, click-and-drag to highlight "
                "the data you want to extract (the same way you'd select the "
                "'check' array), then run Array Extractor again."
            )
            return

        full_text = None
        form = ExtractorForm()
        try:
            ok = form.Execute()
            if not ok:
                return

            type_key = TYPE_KEYS[form.cType.value]
            lang_key = LANG_KEYS[form.cLang.value]
            var_name = (form.sVarName.value or "data").strip() or "data"
            use_hex = (form.cNumFormat.value == 0)

            data = read_bytes_range(start_ea, end_ea)
            if not data:
                ida_kernwin.warning(
                    "Could not read bytes from the selected range.\n"
                    "Make sure it is mapped and loaded."
                )
                return

            big_endian = get_endianness()
            values, kind, addresses = parse_values(data, type_key, big_endian, start_ea)
            if not values:
                ida_kernwin.warning(
                    "No data could be extracted.\n"
                    "The selected range may be smaller than the chosen data type."
                )
                return

            body = format_output(lang_key, values, kind, addresses, var_name, type_key,
                                  ELEMENTS_PER_LINE, use_hex)
            header = build_header(lang_key, start_ea, end_ea, type_key, len(values))
            full_text = header + body
        except Exception as e:
            ida_kernwin.warning("Array Extractor error:\n{}".format(e))
            return
        finally:
            form.Free()

        if not full_text:
            return

        # The input form is fully closed at this point - safe to show the
        # result and, if the user asks for it, touch the clipboard.
        result_form = ResultForm(full_text)
        try:
            wants_copy = result_form.Execute()
        finally:
            result_form.Free()

        if wants_copy:
            if copy_to_clipboard(full_text):
                ida_kernwin.info("Copied to clipboard.")
            else:
                ida_kernwin.warning(
                    "Could not access the system clipboard.\n"
                    "You can reopen the result and select/copy the text manually."
                )

    # --------------------------------------------------------- Action / UI

    class ExtractArrayActionHandler(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            run_extractor()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    class PopupHook(ida_kernwin.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            try:
                wt = ida_kernwin.get_widget_type(widget)
                if wt in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_DUMP, ida_kernwin.BWN_HEXVIEW):
                    ida_kernwin.attach_action_to_popup(widget, popup, ACTION_ID, "Array Extractor/")
            except Exception:
                pass

    class ArrayExtractorPlugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_KEEP
        comment = "Extract a selected data range as a ready-to-paste array"
        help = "Select a data range in the Disassembly/Hex view, pick a data type, " \
               "output language, list name and number format, and get a ready array " \
               "(Python/C/C#/Java/JavaScript)."
        wanted_name = PLUGIN_NAME
        wanted_hotkey = ""  # hotkey lives on the registered action instead

        def init(self):
            action_desc = ida_kernwin.action_desc_t(
                ACTION_ID,
                "Array Extractor...",
                ExtractArrayActionHandler(),
                PLUGIN_HOTKEY,
                "Extract the selected data range as an array",
                199,
            )
            ida_kernwin.register_action(action_desc)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_ID, ida_kernwin.SETMENU_APP)

            self.popup_hook = PopupHook()
            self.popup_hook.hook()
            return ida_idaapi.PLUGIN_KEEP

        def run(self, arg):
            run_extractor()

        def term(self):
            try:
                self.popup_hook.unhook()
            except Exception:
                pass
            try:
                ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_ID)
                ida_kernwin.unregister_action(ACTION_ID)
            except Exception:
                pass

    def PLUGIN_ENTRY():
        return ArrayExtractorPlugin()
