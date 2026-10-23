import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import { reactRefresh } from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig(
    // schema.d.ts is written by `pnpm gen:api` and checked by CI against the API, not by lint.
    globalIgnores(["dist", "playwright-report", "test-results", "src/api/schema.d.ts"]),
    js.configs.recommended,
    tseslint.configs.strictTypeChecked,
    tseslint.configs.stylisticTypeChecked,
    jsxA11y.flatConfigs.recommended,
    reactHooks.configs.flat.recommended,
    reactRefresh.configs.vite(),
    {
        languageOptions: {
            globals: globals.browser,
            parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
        },
        rules: {
            // A template literal of a number or a boolean is how a label gets built; this rule would
            // make every one of them a String() call.
            "@typescript-eslint/restrict-template-expressions": [
                "error",
                { allowNumber: true, allowBoolean: true },
            ],
            "@typescript-eslint/consistent-type-imports": "error",
        },
    },
    {
        files: ["e2e/**/*.ts", "*.config.ts"],
        languageOptions: { globals: globals.node },
    },
    // The config files are plain JavaScript and no tsconfig covers them.
    { files: ["**/*.js"], extends: [tseslint.configs.disableTypeChecked] },
);
