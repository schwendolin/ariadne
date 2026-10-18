/// <reference types="svelte" />
/// <reference types="vite/client" />

/** Mock-Modus fest eingebaut (--mode mock oder VITE_ARIADNE_MOCK=1). */
declare const __ARIADNE_MOCK__: boolean;
/** Version aus package.json (Hilfe, Menü). */
declare const __ARIADNE_VERSION__: string;

interface ImportMetaEnv {
  readonly VITE_ARIADNE_MOCK?: string;
}
