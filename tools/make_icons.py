"""Genere les icones de l'extension QueryShield (16/48/128 px)."""
from PIL import Image, ImageDraw

CYAN = (0, 242, 254, 255)
DARK = (9, 10, 15, 255)
TRANSPARENT = (0, 0, 0, 0)


def shield_path(size):
    """Bouclier symetrique : 4 coins hauts + pointe basse, boite pleine."""
    l, r = 0.18, 0.82          # bords gauche / droit (fraction de size)
    t, b = 0.14, 0.86          # haut / pointe
    sh = 0.34                  # hauteur de l'epaule (fraction)
    return [
        (0.50 * size, t * size),        # sommet
        (r * size, t * size + sh * 0.6 * size),
        (r * size, (t + sh) * size),    # epaule droite basse
        (0.50 * size, b * size),        # pointe
        (l * size, (t + sh) * size),    # epaule gauche basse
        (l * size, t * size + sh * 0.6 * size),
    ]


def check_path(size):
    return [
        (0.35 * size, 0.50 * size),
        (0.45 * size, 0.60 * size),
        (0.68 * size, 0.36 * size),
    ]


def make_icon(size):
    img = Image.new("RGBA", (size, size), TRANSPARENT)
    d = ImageDraw.Draw(img)

    # Fond arrondi sombre
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=int(size * 0.22), fill=DARK)

    # Bouclier : remplissage sombre + contour cyan
    pts = shield_path(size)
    d.polygon(pts, fill=(11, 13, 20, 255))
    w = max(2, round(size * 0.052))
    d.line(pts + [pts[0]], fill=CYAN, width=w, joint="curve")

    # Coche cyan
    cp = check_path(size)
    cw = max(2, round(size * 0.055))
    d.line(cp, fill=CYAN, width=cw, joint="curve")

    return img


for s in (16, 48, 128):
    make_icon(s).save(f"icons/icon{s}.png")
    print(f"icons/icon{s}.png ok")
