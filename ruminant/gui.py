CLANKA_DISCLAIMER = """
I know I rant a lot about clankas but this was partially written by Gemini
(specifically the tkinter part) since I have no experience with GUI and I hate
tkinter but it's the only dependency-free option. I will probably rewrite this
code in the future. The marking logic etc. and everything that is not directly
GUI-related was written by me, though. The GUI part was also extensively
tested by me.

Feel free to stone me or shoot me a PR with a human-made implementation.
"""

has_gui = False
try:
    import tkinter as tk
    from tkinter import ttk

    has_gui = True
except ImportError:
    pass

if has_gui:

    class GUI:
        def __init__(self, root, data):
            self.root = root

            self.marked_tag = "viewed"

            self.setup_styles()
            self.setup_ui()
            self.populate_root(data)

            self.tree.bind("<Return>", self.toggle_mark)
            self.tree.bind("<Shift-space>", self.toggle_fold_recursive)
            self.tree.bind("<Shift-Down>", self.jump_down)
            self.tree.bind("<Shift-Up>", self.jump_up)
            self.tree.bind("<Escape>", lambda _: self.root.destroy())

            children = self.tree.get_children("")
            if children:
                self.tree.event_generate("<<TreeviewSelect>>")
                self.tree.selection_set(children[0])
                self.tree.focus(children[0])
                self.tree.focus_set()

        def setup_styles(self):
            style = ttk.Style()
            style.theme_use("classic")
            style.configure("Treeview", indent=20, font=("Consolas", 10))

            style.map("Treeview", background=[("selected", "#4a6984")])

        def setup_ui(self):
            frame = ttk.Frame(self.root)
            frame.pack(fill=tk.BOTH, expand=True)

            vsb = ttk.Scrollbar(frame, orient="vertical")
            hsb = ttk.Scrollbar(frame, orient="horizontal")

            self.tree = ttk.Treeview(
                frame,
                columns=("value"),
                yscrollcommand=vsb.set,
                xscrollcommand=hsb.set,
                selectmode="browse",
            )

            vsb.config(command=self.tree.yview)
            hsb.config(command=self.tree.xview)

            self.tree.grid(column=0, row=0, sticky="nsew", in_=frame)
            vsb.grid(column=1, row=0, sticky="ns", in_=frame)
            hsb.grid(column=0, row=1, sticky="ew", in_=frame)

            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)

            self.tree.heading("#0", text="Key", anchor=tk.W)
            self.tree.heading("value", text="Value", anchor=tk.W)
            self.tree.column("#0", stretch=False, minwidth=250, width=350)
            self.tree.column("value", stretch=True, width=450)

            self.tree.tag_configure(
                self.marked_tag, background="#90EE90", foreground="#006400"
            )

        def populate_root(self, data):
            self.process_node("", data, depth=0)

        def process_node(self, parent_id, value, depth):
            if isinstance(value, dict):
                for key, val in value.items():
                    self.insert_item(parent_id, key, val, depth, depth == 0)
            elif isinstance(value, list):
                for index, val in enumerate(value):
                    self.insert_item(parent_id, str(index), val, depth, depth == 0)
            else:
                pass

        def toggle_fold_recursive(self, event):
            selected_item = self.tree.focus()
            if not selected_item:
                return "break"

            is_open = self.tree.item(selected_item, "open")
            new_state = not is_open

            self.propagate_fold(selected_item, new_state)

            return "break"

        def propagate_fold(self, item_id, state):
            self.tree.item(item_id, open=state)

            children = self.tree.get_children(item_id)
            for child in children:
                self.propagate_fold(child, state)

        def jump_down(self, event):
            selection = self.tree.focus()
            if not selection:
                return "break"

            next_item = self.tree.next(selection)

            if not next_item:
                parent = self.tree.parent(selection)
                while parent:
                    uncle = self.tree.next(parent)
                    if uncle:
                        next_item = uncle
                        break
                    parent = self.tree.parent(parent)

            if next_item:
                self.select_and_focus(next_item)

            return "break"

        def jump_up(self, event):
            selection = self.tree.focus()
            if not selection:
                return "break"

            prev_item = self.tree.prev(selection)

            if not prev_item:
                parent = self.tree.parent(selection)
                while parent:
                    uncle = self.tree.prev(parent)
                    if uncle:
                        prev_item = uncle
                        break
                    parent = self.tree.parent(parent)

            if prev_item:
                self.select_and_focus(prev_item)

            return "break"

        def select_and_focus(self, item_id):
            self.tree.selection_set(item_id)
            self.tree.focus(item_id)
            self.tree.see(item_id)

        def insert_item(self, parent_id, key, value, depth, is_open):
            item_type = "primitive"
            display_value = str(value)

            if isinstance(value, (dict, list)):
                item_type = "container"
                display_value = ""

            node_id = self.tree.insert(
                parent_id,
                "end",
                text=key,
                values=(display_value,),
                open=is_open,
            )

            if item_type == "container":
                self.process_node(node_id, value, depth + 1)

        def is_marked(self, item_id):
            return self.marked_tag in self.tree.item(item_id, "tags")

        def set_mark(self, item_id, mark=True):
            tags = list(self.tree.item(item_id, "tags"))
            if mark:
                if self.marked_tag not in tags:
                    tags.append(self.marked_tag)
            else:
                if self.marked_tag in tags:
                    tags.remove(self.marked_tag)
            self.tree.item(item_id, tags=tags)

        def toggle_mark(self, event):
            selected_item = self.tree.focus()
            if not selected_item:
                return "break"

            currently_marked = self.is_marked(selected_item)
            new_state = not currently_marked

            self.set_mark(selected_item, new_state)
            self.propagate_down(selected_item, new_state)
            self.propagate_up(selected_item, new_state)

            return "break"

        def propagate_down(self, parent_id, state):
            children = self.tree.get_children(parent_id)
            for child in children:
                self.set_mark(child, state)
                self.propagate_down(child, state)

        def propagate_up(self, item_id, state):
            parent_id = self.tree.parent(item_id)
            if not parent_id:
                return

            if state is False:
                self.set_mark(parent_id, False)
                self.propagate_up(parent_id, False)

            else:
                siblings = self.tree.get_children(parent_id)
                all_siblings_marked = True

                for sibling in siblings:
                    if not self.is_marked(sibling):
                        all_siblings_marked = False
                        break

                if all_siblings_marked:
                    self.set_mark(parent_id, True)
                    self.propagate_up(parent_id, True)

        @classmethod
        def run(cls, data):
            root = tk.Tk()
            cls(root, {"root": data})
            root.mainloop()
