from typing import Optional
from authtuna.core.config import settings


def _get_attr_case_insensitive(obj, name_variants):
    """Return the first attribute value found in obj for any of name_variants."""
    for name in name_variants:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def get_theme_css(mode_override: Optional[str] = None) -> str:
    """
    Returns a <style>...</style> block containing CSS variables for light and dark themes
    derived from application settings. Templates can call this helper as a Jinja global
    (e.g. {{ get_theme_css()|safe }}) to inject consistent colors across pages.

    The function reads colors from settings.THEME.Light and settings.THEME.Dark.
    It is defensive about attribute naming (supports either lowercase or UPPERCASE names).
    """
    theme = settings.THEME

    # Light theme attribute names (variants include uppercase style and camelcase)
    light_bg_start = _get_attr_case_insensitive(theme.Light, [
        "background_color_start", "BACKGROUND_COLOR_START", "bg_start", "BG_START"
    ]) or "#145276FF"
    light_bg_end = _get_attr_case_insensitive(theme.Light, [
        "background_color_end", "BACKGROUND_COLOR_END", "bg_end", "BG_END"
    ]) or "#81CFCAFF"
    light_text = _get_attr_case_insensitive(theme.Light, [
        "text_color", "TEXT_COLOR", "text", "TEXT"
    ]) or "#000000"
    light_icon = _get_attr_case_insensitive(theme.Light, [
        "icon_color", "ICON_COLOR", "icon", "ICON"
    ]) or "#000000"

    # Dark theme attribute names
    dark_bg_start = _get_attr_case_insensitive(theme.Dark, [
        "background_color_start", "BACKGROUND_COLOR_START", "bg_start", "BG_START"
    ]) or "#382C68"
    dark_bg_end = _get_attr_case_insensitive(theme.Dark, [
        "background_color_end", "BACKGROUND_COLOR_END", "bg_end", "BG_END"
    ]) or "#B57CEEFF"
    dark_text = _get_attr_case_insensitive(theme.Dark, [
        "text_color", "TEXT_COLOR", "text", "TEXT"
    ]) or "#FFFFFF"
    dark_icon = _get_attr_case_insensitive(theme.Dark, [
        "icon_color", "ICON_COLOR", "icon", "ICON"
    ]) or "#FFFFFF"

    # Button/accessory defaults derived from the primary background colors
    light_btn_start = light_bg_start
    light_btn_end = light_bg_end
    dark_btn_start = dark_bg_start
    dark_btn_end = dark_bg_end

    css = f"""
<style>
:root {{
  --bg-start: {light_bg_start};
  --bg-end: {light_bg_end};
  --text-color: {light_text};
  --icon-color: {light_icon};
  --btn-bg-start: {light_btn_start};
  --btn-bg-end: {light_btn_end};
  --btn-text: {light_text};
  --muted-text: rgba(0,0,0,0.6);
}}

.dark {{
  --bg-start: {dark_bg_start};
  --bg-end: {dark_bg_end};
  --text-color: {dark_text};
  --icon-color: {dark_icon};
  --btn-bg-start: {dark_btn_start};
  --btn-bg-end: {dark_btn_end};
  --btn-text: {dark_text};
  --muted-text: rgba(255,255,255,0.7);
}}

/* Helpful utility classes that use the theme variables */
.bg-theme-gradient {{
  background: linear-gradient(90deg, var(--bg-start), var(--bg-end));
}}
.text-theme {{
  color: var(--text-color);
}}
.icon-theme {{
  color: var(--icon-color);
}}
.btn-theme {{
  background: linear-gradient(90deg, var(--btn-bg-start), var(--btn-bg-end));
  color: var(--btn-text);
  border: none;
}}
.btn-theme:hover {{
  filter: brightness(0.96);
}}
.btn-theme:focus {{
  box-shadow: 0 0 0 4px rgba(0,0,0,0.08);
  outline: none;
}}
.btn-theme-outline {{
  background: transparent;
  color: var(--btn-text);
  border: 1px solid rgba(255,255,255,0.12);
}}
.btn-theme-outline:hover {{
  background: rgba(255,255,255,0.02);
}}
.muted-theme {{
  color: var(--muted-text);
}}
.brand-circle {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--btn-bg-start), var(--btn-bg-end));
  color: var(--btn-text);
  border-radius: 9999px;
}}
</style>
"""
    return css
