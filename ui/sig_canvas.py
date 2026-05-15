# ui/sig_canvas.py — Pop-up signature drawing window using Tkinter
#
# Colors match banner.py theme exactly.
# Returns a PIL Image of the drawn signature, or None if cancelled.
# Requires: pip install pillow (tkinter is bundled with Python)

import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageDraw

CANVAS_W = 520
CANVAS_H = 240
BORDER_W = 2

BLACK  = "#191a1b"
GREEN  = "#23d18b"
ORANGE = "#ff8700"
GREY   = "#727373"
WHITE  = "#ffffff"
RED    = "#ff5555"
DIM    = "#2a2a2a"

PEN_COLOR = ORANGE
PEN_WIDTH = 3
TITLE     = "file2enc — Signature Authentication"


class SignatureCanvas:
    def __init__(self, prompt: str = "Draw your signature, then click Confirm."):
        self.root     = tk.Tk()
        self.root.title(TITLE)
        self.root.resizable(False, False)
        self.root.configure(bg=BLACK)
        self.result   = None
        self._last_xy = None
        self._strokes = []
        self._build_ui(prompt)

    def _build_ui(self, prompt: str):
        # ── Header ─────────────────────────────────────────────────────────────
        tk.Label(
            self.root,
            text="✦  Signature Authentication",
            bg=BLACK, fg=ORANGE,
            font=("Consolas", 13, "bold"), pady=8
        ).pack()

        tk.Label(
            self.root, text=prompt,
            bg=BLACK, fg=GREY,
            font=("Consolas", 10), pady=2
        ).pack()

        # ── Outer canvas — draws the green border + hosts the drawing area ─────
        PAD     = BORDER_W + 4
        OUTER_W = CANVAS_W + PAD * 2
        OUTER_H = CANVAS_H + PAD * 2

        outer = tk.Canvas(
            self.root,
            width=OUTER_W, height=OUTER_H,
            bg=BLACK, highlightthickness=0
        )
        outer.pack(padx=12, pady=10)

        # Plain green rectangle border
        outer.create_rectangle(
            PAD - BORDER_W, PAD - BORDER_W,
            OUTER_W - PAD + BORDER_W, OUTER_H - PAD + BORDER_W,
            outline=GREEN, fill="", width=BORDER_W
        )

        # ── Drawing canvas inside the outer one ────────────────────────────────
        self.canvas = tk.Canvas(
            outer,
            width=CANVAS_W, height=CANVAS_H,
            bg=BLACK, cursor="crosshair",
            highlightthickness=0
        )
        outer.create_window(OUTER_W // 2, OUTER_H // 2, window=self.canvas)

        # Watermark
        self._watermark = self.canvas.create_text(
            CANVAS_W // 2, CANVAS_H // 2,
            text="Sign here", fill=GREY,
            font=("Consolas", 26, "italic")
        )

        self.canvas.bind("<ButtonPress-1>",   self._on_press)
        self.canvas.bind("<B1-Motion>",       self._on_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)

        # ── Buttons ────────────────────────────────────────────────────────────
        btn_frame = tk.Frame(self.root, bg=BLACK)
        btn_frame.pack(pady=(0, 12))

        tk.Button(
            btn_frame, text="  Clear  ", command=self._clear,
            bg=DIM, fg=GREY,
            font=("Consolas", 10), relief="flat",
            activebackground="#333333", activeforeground=WHITE,
            padx=10, pady=4
        ).pack(side="left", padx=8)

        tk.Button(
            btn_frame, text="  Confirm  ", command=self._confirm,
            bg=GREEN, fg=BLACK,
            font=("Consolas", 10, "bold"), relief="flat",
            activebackground="#1aab6d", activeforeground=BLACK,
            padx=10, pady=4
        ).pack(side="left", padx=8)

        tk.Button(
            btn_frame, text="  Cancel  ", command=self._cancel,
            bg=DIM, fg=RED,
            font=("Consolas", 10), relief="flat",
            activebackground="#333333", activeforeground=RED,
            padx=10, pady=4
        ).pack(side="left", padx=8)

        # Centre on screen
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        w  = self.root.winfo_width()
        h  = self.root.winfo_height()
        self.root.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    # ── Drawing callbacks ──────────────────────────────────────────────────────

    def _on_press(self, e):
        if self.canvas.find_withtag(self._watermark):
            self.canvas.delete(self._watermark)
        self._last_xy = (e.x, e.y)
        self._strokes.append(("start", e.x, e.y))

    def _on_drag(self, e):
        if self._last_xy:
            x0, y0 = self._last_xy
            self.canvas.create_line(
                x0, y0, e.x, e.y,
                fill=PEN_COLOR, width=PEN_WIDTH,
                capstyle=tk.ROUND, joinstyle=tk.ROUND, smooth=True
            )
            self._last_xy = (e.x, e.y)
            self._strokes.append(("line", x0, y0, e.x, e.y))

    def _on_release(self, _):
        self._last_xy = None
        self._strokes.append(("end",))

    # ── Actions ────────────────────────────────────────────────────────────────

    def _clear(self):
        self.canvas.delete("all")
        self._watermark = self.canvas.create_text(
            CANVAS_W // 2, CANVAS_H // 2,
            text="Sign here", fill=GREY,
            font=("Consolas", 26, "italic")
        )
        self._strokes.clear()

    def _confirm(self):
        if not any(s[0] == "line" for s in self._strokes):
            messagebox.showwarning(
                "Empty Signature",
                "Please draw your signature before confirming.",
                parent=self.root
            )
            return
        self.result = self._render_image()
        self.root.destroy()

    def _cancel(self):
        self.result = None
        self.root.destroy()

    def _render_image(self) -> Image.Image:
        """Rasterise strokes to a PIL image for storage and comparison."""
        img  = Image.new("RGB", (CANVAS_W, CANVAS_H), color=(25, 26, 27))
        draw = ImageDraw.Draw(img)
        for stroke in self._strokes:
            if stroke[0] == "line":
                x0, y0, x1, y1 = stroke[1], stroke[2], stroke[3], stroke[4]
                draw.line([(x0, y0), (x1, y1)], fill=(35, 209, 139), width=PEN_WIDTH)
        return img

    def show(self) -> "Image.Image | None":
        self.root.mainloop()
        return self.result


def capture_signature(prompt: str = "Draw your signature, then click Confirm.") -> "Image.Image | None":
    return SignatureCanvas(prompt).show()