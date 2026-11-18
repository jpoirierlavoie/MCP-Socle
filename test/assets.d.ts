declare module "*.md?raw" {
  const contenu: string;
  export default contenu;
}

declare module "*.json?raw" {
  const contenu: string;
  export default contenu;
}

declare module "*.ts?raw" {
  const contenu: string;
  export default contenu;
}

declare module "*LICENSE?raw" {
  const contenu: string;
  export default contenu;
}

declare module "*.toml?raw" {
  const contenu: string;
  export default contenu;
}

interface ImportMeta {
  readonly glob: <T = unknown>(
    pattern: string | string[],
    options?: { query?: string; import?: string; eager?: boolean },
  ) => Record<string, T>;
}

declare namespace Cloudflare {
  interface Env {
    DB_IDENTITE_TEST: D1Database;
  }
}
