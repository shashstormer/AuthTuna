from typing import Optional
from authtuna.core.config import settings


def get_theme_css(mode_override: Optional[str] = None) -> str:
    """
    Returns a <style>...</style> block containing CSS variables for light and dark themes
    derived from the application settings. This allows for dynamic and configurable
    theming of the UI components.
    """
    theme_config = settings.THEME
    light = theme_config.light
    dark = theme_config.dark

    # Generate CSS variables for both light and dark themes from the Pydantic models
    light_vars = "; ".join(f"--{key.replace('_', '-')}: {value}" for key, value in light.model_dump().items())
    dark_vars = "; ".join(f"--{key.replace('_', '-')}: {value}" for key, value in dark.model_dump().items())

    # Determine the default theme based on the configuration
    if theme_config.mode == "system":
        # System preference will be handled by a media query
        default_vars = light_vars
        dark_mode_selector = "@media (prefers-color-scheme: dark) { :root { " + dark_vars + "; } }"
    elif theme_config.mode == "multi" or mode_override == "dark":
        # Default to light, but allow override via a `.dark` class
        default_vars = light_vars
        dark_mode_selector = ".dark { " + dark_vars + "; }"
    else:  # single mode (light)
        default_vars = light_vars
        dark_mode_selector = ""

    css = f"""
<style>
:root {{
  {default_vars};

  --radius: 0.5rem;
}}

{dark_mode_selector}

/* Reset and base styles */
body {{
  background: linear-gradient(135deg, var(--background-start), var(--background-end));
  color: var(--foreground);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}}

/* General purpose utility classes */
.card {{
  background-color: var(--card);
  color: var(--card-foreground);
  border-radius: var(--radius);
  border: 1px solid var(--border);
  box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
}}

.btn-primary {{
  background-color: var(--primary);
  color: var(--primary-foreground);
  padding: 0.5rem 1rem;
  border-radius: var(--radius);
  text-align: center;
  font-weight: 600;
  border: none;
  cursor: pointer;
  transition: filter 0.2s ease-in-out;
}}
.btn-primary:hover {{ filter: brightness(0.9); }}
.btn-primary:focus {{ box-shadow: 0 0 0 4px var(--ring); outline: none; }}

.btn-secondary {{
  background-color: var(--secondary);
  color: var(--secondary-foreground);
  padding: 0.5rem 1rem;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  cursor: pointer;
  transition: background-color 0.2s ease;
}}
.btn-secondary:hover {{ background-color: var(--accent); }}

.form-input {{
  background-color: var(--card);
  color: var(--foreground);
  border: 1px solid var(--input);
  border-radius: var(--radius);
  padding: 0.5rem 0.75rem;
  width: 100%;
}}
.form-input:focus {{
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 2px var(--ring);
}}

.text-muted {{
  color: var(--muted-foreground);
}}

a {{
  color: var(--primary);
  text-decoration: none;
}}
a:hover {{
  text-decoration: underline;
}}
</style>
"""
    return css
