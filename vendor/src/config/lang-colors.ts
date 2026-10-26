// Language colors — a tiny palette so language-mix bars read at a glance.
// Unknown languages fall back to LANG_FALLBACK_COLOR. Shared by the /gh page
// and compare mode.
export const LANG_COLORS: Record<string, string> = {
  TypeScript: "#3178c6",
  JavaScript: "#f1e05a",
  Python: "#3572A5",
  Go: "#00ADD8",
  Rust: "#dea584",
  Ruby: "#701516",
  Java: "#b07219",
  Kotlin: "#A97BFF",
  Swift: "#F05138",
  "C++": "#f34b7d",
  C: "#555555",
  "C#": "#178600",
  PHP: "#4F5D95",
  HTML: "#e34c26",
  CSS: "#563d7c",
  Shell: "#89e051",
  Vue: "#41b883",
  Svelte: "#ff3e00",
};

export const LANG_FALLBACK_COLOR = "hsl(var(--muted-foreground) / 0.4)";
