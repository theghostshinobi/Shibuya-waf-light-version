<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import * as monaco from "monaco-editor";
    // Note: Monaco worker Configuration usually required in Vite, but we try basic import first.
    // If it fails, we might need a worker shim.
    import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";
    import jsonWorker from "monaco-editor/esm/vs/language/json/json.worker?worker";
    import cssWorker from "monaco-editor/esm/vs/language/css/css.worker?worker";
    import htmlWorker from "monaco-editor/esm/vs/language/html/html.worker?worker";
    import tsWorker from "monaco-editor/esm/vs/language/typescript/ts.worker?worker";

    self.MonacoEnvironment = {
        getWorker: function (_moduleId, label) {
            if (label === "json") {
                return new jsonWorker();
            }
            if (label === "css" || label === "scss" || label === "less") {
                return new cssWorker();
            }
            if (
                label === "html" ||
                label === "handlebars" ||
                label === "razor"
            ) {
                return new htmlWorker();
            }
            if (label === "typescript" || label === "javascript") {
                return new tsWorker();
            }
            return new editorWorker();
        },
    };

    export let value = "";

    let editorContainer: HTMLElement;
    let editor: monaco.editor.IStandaloneCodeEditor;

    onMount(() => {
        // Initialize Monaco Editor
        editor = monaco.editor.create(editorContainer, {
            value,
            language: "yaml",
            theme: "vs-dark",
            automaticLayout: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            fontSize: 14,
            lineNumbers: "on",
            folding: true,
        });

        // Update value on change
        editor.onDidChangeModelContent(() => {
            value = editor.getValue();
        });
    });

    onDestroy(() => {
        editor?.dispose();
    });

    // Update editor when value changes externally
    $: if (editor && value !== editor.getValue()) {
        editor.setValue(value);
    }
</script>

<div class="yaml-editor" bind:this={editorContainer}></div>

<style>
    .yaml-editor {
        width: 100%;
        height: 70vh;
        border: 1px solid #333;
    }
</style>
