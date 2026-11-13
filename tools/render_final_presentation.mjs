import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const root=path.resolve(import.meta.dirname,'..');
const {PresentationFile,FileBlob}=await import(pathToFileURL(process.env.WEBSEC_ARTIFACT_MODULE || 'C:/Users/Scout/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs'));
const deck=await PresentationFile.importPptx(await FileBlob.load(path.join(root,'deliverables/点击劫持项目答辩.pptx')));
const out=path.join(root,'.websec-local/presentation-final');await fs.mkdir(out,{recursive:true});
for(const [i,slide] of deck.slides.items.entries()){
 const blob=await deck.export({slide,format:'png',scale:1});
 await fs.writeFile(path.join(out,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await blob.arrayBuffer()));
}
console.log(JSON.stringify({renderedSlides:deck.slides.items.length,out}));
