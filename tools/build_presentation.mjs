import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const ROOT=path.resolve(import.meta.dirname,'..');
const RUNTIME=process.env.WEBSEC_ARTIFACT_MODULE || 'C:/Users/Scout/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/@oai/artifact-tool/dist/artifact_tool.mjs';
process.env.RUNTIME_NODE_MODULES ||= path.resolve(path.dirname(RUNTIME),'../../..');
const SKILL=process.env.WEBSEC_PRESENTATION_SKILL || 'E:/CodexData/plugins/cache/openai-primary-runtime/presentations/26.1030.10813/skills/presentations';
const {Presentation,PresentationFile}=await import(pathToFileURL(RUNTIME));
const {applyPresentationChartFont,finalizePresentation}=await import(pathToFileURL(path.join(SKILL,'container_tools/artifact_tool_utils.mjs')));
const FONT='Microsoft YaHei', C={navy:'#10233F',blue:'#2563EB',orange:'#D95C37',muted:'#58677D',line:'#D5DDE8',bg:'#F8FAFC'};
const build=path.join(ROOT,'.websec-local/presentation-build');
await fs.mkdir(build,{recursive:true});
const deck=Presentation.create({slideSize:{width:1280,height:720}});
let facts={}; try {facts=JSON.parse(await fs.readFile(path.join(ROOT,'deliverables/data/facts.json'),'utf8'));}catch{}

function shape(s,geometry,x,y,w,h,fill,line='none'){
  return s.shapes.add({geometry,position:{left:x,top:y,width:w,height:h},fill,line:{fill:line,width:line==='none'?0:1,style:'solid'}});
}
function text(s,value,x,y,w,h,size=28,color=C.navy,bold=false){
  const sh=shape(s,'textbox',x,y,w,h,'none'); sh.text=String(value);
  sh.text.style={fontSize:size,typeface:FONT,color,bold}; return sh;
}
function slide(title,note=''){
  const s=deck.slides.add();s.background.fill=C.bg;
  text(s,title,64,46,1152,80,38,C.navy,true);
  shape(s,'rect',64,142,1152,3,C.blue);
  text(s,String(deck.slides.items.length).padStart(2,'0'),1170,668,48,26,16,C.muted);
  s.speakerNotes.text=note;return s;
}
function lines(s,items,x=70,y=195,w=1130,size=28,gap=88){
  items.forEach((item,i)=>text(s,item,x,y+i*gap,w,gap-14,size));
}
function table(s,values,widths,y=194,height=370,size=23){
  const tb=s.tables.add({rows:values.length,columns:values[0].length,left:64,top:y,width:1152,height,values,columnWidths:widths});
  tb.borders.assign({fill:C.line,width:1,style:'solid'});
  tb.cells.block({row:0,column:0,rowCount:values.length,columnCount:values[0].length}).assign({textStyle:{fontSize:size,typeface:FONT,color:C.navy},margins:{left:12,right:12,top:12,bottom:12}});
  tb.cells.block({row:0,column:0,rowCount:1,columnCount:values[0].length}).assign({fill:C.navy,textStyle:{fontSize:size,typeface:FONT,color:'#FFFFFF',bold:true}});
  return tb;
}
function chart(s,categories,series,position={left:64,top:192,width:1152,height:416}){
  const ch=s.charts.add('bar',{position,categories,series,hasLegend:series.length>1,
    dataLabels:{showValue:true,position:'outEnd'},
    xAxis:{majorGridlines:{fill:C.line,width:1}}, yAxis:{}});
  applyPresentationChartFont(ch,{fontFamily:FONT});
  for(const style of [ch.legend?.textStyle,ch.dataLabels?.textStyle,ch.xAxis?.textStyle,ch.yAxis?.textStyle]){
    if(style)style.fontSize=22;
  }
  return ch;
}

const cover=deck.slides.add();cover.background.fill=C.navy;
text(cover,'点击劫持的分析与防御',72,140,1120,100,58,'#FFFFFF',true);
text(cover,'多域 HTTPS 靶场 · 分层防御 · 双通道审计',76,264,1080,58,30,'#B9D1F3');
shape(cover,'rect',78,382,352,138,'#FFFFFF');
text(cover,'可见界面',102,396,302,34,23,C.muted);
text(cover,'点击领取奖励',102,446,302,46,30,C.blue,true);
shape(cover,'rect',484,382,350,138,'#2D548A');
text(cover,'透明嵌入层',508,396,300,34,23,'#C8DFFB');
text(cover,'确认模拟转账',508,446,300,46,30,'#FFFFFF',true);
shape(cover,'rightArrow',442,424,35,35,C.orange);
text(cover,'从用户点击到服务端状态，验证防御的实际效果',76,596,1120,44,25,'#E1EAF8');
cover.speakerNotes.text='成员一开场：本项目研究用户所见界面与实际操作对象不一致的点击劫持。我们用虚构业务与真实浏览器构建实验，分别观察嵌入、会话、点击、业务结果和审计信号。所有目标属于本机靶场。';

if(!process.argv.includes('--cover-only')){
 let s=slide('问题与评估目标','成员一：三个观察对象分别是浏览器能否嵌入、会话能否发送、敏感操作是否执行。iframe的load不能单独证明攻击成立。证据：项目报告、逐例服务端状态。');
 lines(s,['页面能否被嵌入：验证 XFO / CSP 的执行结果','会话是否随请求发送：验证 SameSite 与第三方 Cookie 设置','点击是否执行操作：核对转账、授权及余额的实际变化']);
 s=slide('五域 HTTPS 靶场','成员一：victim.test与same.victim.test同站不同源；attacker.test跨站。Nginx终止TLS，后端均位于回环地址。CA与SNI验证保持开启。来源：config/lab.https.yaml。');
 const boxes=[['目标网站\nvictim.test',64,225,C.blue],['同站诱导\nsame.victim.test',440,225,C.orange],['跨站诱导\nattacker.test',816,225,C.orange],['合法合作方\npartner.test',256,425,C.blue],['审计服务\naudit.test',632,425,C.blue]];
 for(const [label,x,y,color] of boxes){shape(s,'rect',x,y,336,112,color);text(s,label,x+18,y+12,300,86,27,'#FFFFFF',true);}
 text(s,'同站关系由协议与可注册域共同决定，端口不同不会自动变成跨站',66,594,1146,44,24,C.muted);
 s=slide('三类核心点击劫持','成员一：overlay是近透明覆盖；clip使用可见控件配合裁剪；multistep先授权再转账。自动化按场景真正分发，多步骤分别检查两类状态。来源：dynamic/runner.py，原始实验数据。');
 table(s,[['场景','界面机制','业务核对'],['透明覆盖','近透明 iframe 与诱导按钮重合','转账 + 余额差'],['界面裁剪','仅显示目标的确认控件','转账 + 余额差'],['多步骤诱导','授权 → 转账两阶段','授权 + 转账 + 余额差']],[220,490,442],204,350);
 s=slide('一次点击的完整证据链','成员一：真正接收点击的是嵌入的目标控件。页面事件只表示浏览器交互；是否形成影响以服务器交易记录与余额为准。我们保留每例截图、报告和原始状态。');
 const flow=['诱导按钮坐标','目标控件接收','合法表单提交','服务端状态变化'];
 flow.forEach((v,i)=>{shape(s,'rect',64+i*294,238,258,108,i===3?C.orange:C.blue);text(s,v,80+i*294,265,226,62,25,'#FFFFFF',true);if(i<3)shape(s,'rightArrow',330+i*294,270,26,38,C.muted);});
 text(s,'成功证据：新增 1 笔模拟转账，余额减少 123 分',70,429,1130,56,32,C.navy,true);
 text(s,'多步骤还需核对授权记录；业务结果与审计信号独立保存',70,516,1130,54,25,C.muted);
 s=slide('窗口切换路径与框架策略边界','成员一：受控实验先打开目标窗口，再打开诱导窗口。第一次mousedown关闭诱导窗口，第二次坐标点击落入目标。输入由浏览器协议发送，不能直接外推任意操作系统窗口堆叠。证据：window类原始数据和截图。');
 lines(s,['窗口实验不依赖 iframe 嵌入','第一次按下鼠标关闭诱导窗口，随后点击作用于目标页','XFO / frame-ancestors 的框架限制不等于顶层窗口交互限制','按具体页面和交互预算验证业务确认机制'],70,190,1125,27,90);
 s=slide('四个防御层次','成员二：每层控制不同条件。框架控制限制嵌入，会话控制限制身份，业务控制约束状态变化，审计输出提供可疑行为定位。不能混淆配置存在与攻击被阻断。');
 table(s,[['层次','机制','控制对象'],['浏览器嵌入','XFO / CSP frame-ancestors','允许哪些来源嵌入'],['身份会话','SameSite / Secure / 第三方 Cookie','能否携带有效会话'],['业务授权','分步确认 / 一次性令牌 / 重新认证','操作是否满足服务端条件'],['运行审计','CSP 报告 / 目标页交互信号','发生了哪些可观测事件']],[218,500,434],184,420,22);
 s=slide('XFO 与 CSP 的来源语义','成员二：XFO DENY完全拒绝，SAMEORIGIN按origin检查；CSP可以精确允许partner。冲突与重复头按真实浏览器结果对比。标准：https://www.rfc-editor.org/rfc/rfc7034；https://www.w3.org/TR/CSP3/#directive-frame-ancestors。');
 lines(s,["X-Frame-Options: DENY / SAMEORIGIN","Content-Security-Policy: frame-ancestors 'none'","Content-Security-Policy: frame-ancestors 'self' https://partner.test:8443",'静态预测与动态结果使用同一响应、同一会话条件和实际来源'],70,198,1130,25,92);
 s=slide('SameSite 跨站实验结果','成员二：本表来自96例专项实验，2浏览器×4 Cookie配置×2站点关系×2第三方设置×3重复。None无Secure被拒绝保存。Lax与Strict通过顶层GET对照区分。数据：artifacts/samesite-https。标准：https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie。');
 table(s,[['Cookie','同站 iframe','跨站：允许 3PC','跨站：阻止 3PC'],['Strict + Secure','携带会话','不携带','不携带'],['Lax + Secure','携带会话','不携带','不携带'],['None + Secure','携带会话','携带会话','不携带'],['None 无 Secure','拒绝保存','拒绝保存','拒绝保存']],[300,280,286,286],184,370,23);
 text(s,'跨站顶层 GET：Lax 携带会话，Strict 不携带',70,590,1130,48,27,C.blue,true);
 s=slide('业务防御的实际效果','成员二：一次性令牌和CSRF令牌可以校验请求，但点击劫持使用目标页面生成的合法表单。二次确认的效果取决于攻击的点击预算；重新认证也取决于会话有效期。数字来自最终数据，不把页面加载视为业务影响。');
 table(s,facts.businessTable || [['配置','操作触发 / 实验数'],['本轮数据','采集后生成']],[640,512],190,355,25);
 s=slide('合法嵌入需要同时满足策略与会话','成员二：CSP允许partner只能保证框架条件。Lax跨站会话缺失会使组件显示登录页；None+Secure在允许第三方Cookie的对照下恢复组件功能。判定同时检查frame verdict及实际组件URL。');
 table(s,facts.partnerTable || [['配置','框架允许','组件功能'],['本轮数据','采集后生成','采集后生成']],[578,287,287],198,330,24);
 text(s,'合法敏感嵌入也是正常交互基线，用于检验启发式误报',70,581,1130,48,26,C.muted);
 s=slide('静态分析与真实浏览器联合验证','成员三：先解析策略，后在指定来源中加载；比较阶段使用浏览器实际获取的文档响应，不用匿名请求的登录重定向替代。若缺失证据则输出不确定，不把unknown写成安全。来源：auditor/report.py。');
 lines(s,['静态：XFO、CSP、Cookie、策略冲突与白名单','动态：实际探针来源、文档响应、浏览器安全信息、真实点击','业务：独立查询服务端状态，确认敏感操作是否执行','输出：JSON / Markdown / HTML 与逐例证据'],70,190,1130,28,90);
 s=slide('双通道采集与证据关联','成员三：通道一是浏览器CSP报告，通道二是目标页脚本上报。按run_id、页面路径和两秒窗口关联；客户端启发式使用嵌入中的敏感点击或快速焦点后点击。检测规则不读取业务成功标签。');
 shape(s,'rect',64,218,470,110,C.blue);text(s,'通道一：CSP 违规报告',86,248,428,60,29,'#FFFFFF',true);
 shape(s,'rect',64,389,470,110,C.orange);text(s,'通道二：目标页交互',86,420,428,60,29,'#FFFFFF',true);
 shape(s,'rightArrow',559,302,82,61,C.muted);
 lines(s,['按实验编号关联','按页面路径定位','按时间窗口聚合','输出风险与原始证据'],690,215,500,28,78);
 s=slide('单通道与融合消融结果','成员三：统计口径区分攻击尝试、成功攻击和正常对照。融合的收益来自互补信号，不能把可疑信号等同于攻击成功。窗口无信号路径和合法嵌入误报保留在数据中。来源：最终汇总与消融表。');
 if(facts.ablationChart)chart(s,facts.ablationChart.categories,facts.ablationChart.series);
 else lines(s,['CSP 报告覆盖部分受限嵌入尝试','交互信号覆盖已渲染的目标交互','融合采用联合观察，误报由正常基线独立评估']);
 text(s,'融合：尝试覆盖 657/891，成功攻击覆盖 414/459，正常误报 10/27',70,620,1130,36,22,C.muted);
 s=slide('浏览器与防御配置对照','成员三：该表按浏览器汇总桌面三种核心攻击，所有比例带实际分母。缺少结果或执行错误不作为成功/安全结果。来源：最终矩阵原始JSON。');
 table(s,facts.browserTable || [['浏览器','操作触发','有效实验'],['采集后生成','—','—']],[512,320,320],205,330,25);
 s=slide('实验规模与状态隔离','成员三：基础矩阵覆盖全部配置、三个核心攻击、三个浏览器和三次重复；扩展窗口、移动视口、合法嵌入和正常控制单独标记。SameSite专项96例单独报告。');
 lines(s,[`防御配置：${facts.profiles ?? '待汇总'} 种；浏览器：Chrome / Edge / Firefox`,
   `主实验与控制：${facts.rows ?? '待汇总'} 例；SameSite 专项：96 例`,
   '每种配置独立数据库，每例重置，浏览器会话独立',
   '每例保留实验参数、实际版本、业务增量、信号与截图'],70,190,1130,28,88);
 s=slide('信号能够证明什么','成员三：强调结论层次。服务端状态可证明模拟操作发生，CSP可以证明策略违规上报，页面信号可以定位可疑点击，但不能独立证明用户意图。合法敏感嵌入与窗口无信号路径刻画适用边界。');
 lines(s,['业务状态证明操作是否发生','CSP 报告记录策略违规；页面信号记录可观测交互','正常嵌入中的敏感点击，可能与恶意诱导产生相似信号','窗口路径可能缺少可用信号，需要业务约束共同防护'],70,190,1130,28,90);
 s=slide('复现与交付','成员三：README给出Windows Conda与Docker两条路径；容器运行、配置切换、最小审计与完整矩阵均有命令。交付包附文件哈希、版本与许可证清单。');
 lines(s,['Windows：Websec 环境 + 本地 Nginx + 用户 CA','Linux：docker compose up -d --build','审计：analyze / audit / audit-report --signals','交付：源码、原始数据、报告、PPT、演示视频、三人讲稿'],70,192,1130,28,90);
 s=slide('三人汇报与演示安排','成员一负责攻击和靶场，成员二负责分层防御和兼容性，成员三负责审计、实验和复现。每人均讲解代码、演示行为和解释一组实验结果。详细逐页讲稿与问答见交付文档。');
 table(s,[['成员','汇报内容','演示与证据'],['成员一','攻击机制、架构、窗口扩展','三类攻击与业务状态'],['成员二','策略、Cookie、业务确认','阻断与合法嵌入对照'],['成员三','审计、双通道、实验','报告、消融和复现']],[216,490,446],205,340,25);
 s=slide('项目结论','三人共同收束：点击劫持评估必须连接来源、会话、交互与业务状态。框架、Cookie和业务层各控制不同条件；双通道提供可解释的观察。所有结果可追溯到本机实验和原始证据。');
 lines(s,['以真实浏览器和服务端状态验证防御效果','区分嵌入权限、会话条件与业务授权','用合法来源与正常交互检验兼容性和误报','保留原始证据，使结果可以复核与重现'],70,190,1130,30,91);
}

await (await PresentationFile.exportPptx(deck)).save(path.join(build,'candidate.pptx'));
for(const [i,s] of deck.slides.items.entries()){
 const png=await deck.export({slide:s,format:'png',scale:1});
 await fs.writeFile(path.join(build,`slide-${String(i+1).padStart(2,'0')}.png`),new Uint8Array(await png.arrayBuffer()));
}
if(process.argv.includes('--final')){
 const finalPath=path.join(ROOT,'deliverables/点击劫持项目答辩.pptx');
 await fs.mkdir(path.dirname(finalPath),{recursive:true});
 await finalizePresentation({workspaceDir:ROOT,candidatePath:path.join(build,'candidate.pptx'),finalPath,
  pythonExecutable:process.env.WEBSEC_AUTHORING_PYTHON || 'C:/Users/Scout/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe',
  integrityValidatorPath:path.join(SKILL,'container_tools/inspect_presentation_package_integrity.py'),
  layoutValidatorPath:path.join(SKILL,'container_tools/inspect_presentation_layout_geometry.py'),
  layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-heading-fit',
   ...[4,7,9,10,11,15,19].flatMap(n=>['--require-native-table-slide',String(n)])],
  explicitTotalSlideCount:20,requiredNativeTableOwnerSlides:[4,7,9,10,11,15,19],requiredNativeChartOwnerSlides:[14],
  materializeLiteralChartWorkbooks:true,fontPolicy:{basis:'design',families:[FONT,'Arial']},
  verifyArtifactToolImport:true,receiptPath:path.join(build,'validation.json')});
}
console.log(JSON.stringify({slides:deck.slides.items.length,build}));
