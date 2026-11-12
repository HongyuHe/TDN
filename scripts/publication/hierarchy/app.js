'use strict';
const data=JSON.parse(document.querySelector('#hierarchy-data').textContent);
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sourceURL=n=>data.codeBase ? `${data.codeBase}/${n.path}#L${n.line}` : `vscode://file${data.root}/${n.path}:${n.line}`;
$('#trust-policy').href=sourceURL({path:'docs/proof_trust.md',line:1});
const isProof=n=>['theorem','lemma'].includes(n.kind);
const requirementSpecs=new Map(data.groups.filter(g=>g.formal).map(g=>[g.formal,g.id]));
const kindLabel=n=>({def:'Definition',abbrev:'Abbreviation',structure:'Record type',inductive:'Inductive type',lemma:'Lemma',theorem:'Theorem'}[n.kind]||n.kind);
const categories={specification:'Specifications',general:'General proofs',snapshot:'Model applications and checks',support:'Other definitions'};
function categoryOf(name){
 if(group.specifications.includes(name))return 'specification';
 const n=data.nodes[name];
 if(isProof(n)&&n.path.startsWith('TDN/Deployments/'))return 'snapshot';
 if(isProof(n)&&n.path.startsWith('TDN/'))return 'general';
 return 'support';
}
function renderPicker(){
 const query=$('#declaration-search').value.toLowerCase().trim();
 const category=$('#proof-category').value;
 const matches=group.choices.filter(n=>(category==='all'||categoryOf(n)===category)&&
  query.split(/\s+/).every(word=>[n,data.nodes[n].path].join(' ').toLowerCase().includes(word)));
 matchingNames=matches;
 if(matches.length){if(!matches.includes(root))root=matches[0];}else root=group.formal;
 const count=matches.filter(n=>n!==group.formal).length,total=Math.max(0,group.choices.length-1);
 $('#choice-count').textContent=`${count} of ${total} related definitions and proofs shown below ${group.id}’s specification. ${count?'Click a second-layer box to expand or collapse its dependencies.':'Clear the search or select another category.'}`;
 return matches;
}
function inspect(name){
 if(!group.choices.includes(name))return;
 root=name;selectedKey=null;$('#declaration-search').value='';$('#proof-category').value=categoryOf(name);
 renderPicker();renderGraph();requestAnimationFrame(()=>focusNode(name));
}
function renderRelatedSpecification(){
 const spec=group.specifications.includes(root)?root:group.specifications.find(n=>data.nodes[n].canonicalName===data.nodes[root]?.canonicalHead);
 const candidates=group.specificationProofs[spec]||[];
 const general=candidates.filter(n=>categoryOf(n)==='general');
 const applicationOrder=Object.keys(group.applications);
 const applicationRank=n=>n===group.countedApplication?-1:applicationOrder.includes(n)?applicationOrder.indexOf(n):applicationOrder.length;
 const concrete=candidates.filter(n=>categoryOf(n)==='snapshot').sort((a,b)=>applicationRank(a)-applicationRank(b));
 const buttons=[];
 if(spec&&spec!==root&&group.specifications.includes(spec))buttons.push(`<button data-inspect="${esc(spec)}">Read specification: ${esc(data.nodes[spec].short)}</button>`);
 if(group.specifications.includes(root)){
  if(general.length)buttons.push(`<button data-inspect="${esc(general[0])}">Locate its general proof</button>`);
  if(concrete.length)buttons.push(`<button data-inspect="${esc(concrete[0])}">Locate a model application</button>`);
 }
 $('#related-specification').innerHTML=buttons.join('');
 $('#related-specification').querySelectorAll('[data-inspect]').forEach(b=>b.onclick=()=>inspect(b.dataset.inspect));
}
let group,root,layout,selected,selectedKey=null,zoom=1,matchingNames=[];
const expanded=new Set();
const branchCache=new Map();
let locatorMatches=[],locatorIndex=0;
const initial=new URLSearchParams(location.hash.slice(1));
let activeID=initial.get('target')||'RG-034';
if(!data.groups.some(g=>g.id===activeID))activeID='RG-034';
const coverage=data.metadata.summary;
$('#coverage-summary').textContent=`${coverage.formal_definitions} selected specifications: ${coverage.review_pass_groups} complete proofs passed review; ${coverage.deferred_groups} deferred. The other ${coverage.outside_selected_groups} RGs remain catalog entries.`;
$('#source-summary').textContent=`TDN ${data.metadata.version}: ${coverage.formal_definitions} accepted specifications, ${coverage.review_pass_groups} reviewed complete general proofs, and ${coverage.deferred_groups} deferred targets. Status comes from the recorded complete-candidate reviews. Dependencies and source links were refreshed from the current Lean development. ${coverage.complete_model_applications} registered complete model applications use the reviewed general proofs. Applying those results to a live deployment requires the stated observation and implementation assumptions.`;
function renderTargets(){
 const query=$('#search').value.toLowerCase();
 const matches=data.groups.filter(g=>[g.id,g.title,g.target,g.targetName,...g.choices].join(' ').toLowerCase().includes(query));
 $('#target-count').textContent=`${matches.length} of 76 groups`;
 $('#compact-target').innerHTML=matches.map(g=>`<option value="${g.id}" ${g.id===activeID?'selected':''}>${g.id}: ${esc(g.title)}</option>`).join('');
 $('#target-list').innerHTML=matches.map(g=>`<button class="target-button ${g.status}" data-target="${g.id}" title="${esc(g.id+': '+g.title+' — '+data.statusLabels[g.status])}" aria-label="${esc(g.id+': '+g.title)}" aria-current="${g.id===activeID}"><span class="number">${g.id}</span><span class="target-name">${esc(g.title)}</span></button>`).join('');
 $('#target-list').querySelectorAll('button').forEach(b=>b.onclick=()=>chooseGroup(b.dataset.target));
}
function chooseGroup(id,desired){
 activeID=id;group=data.groups.find(g=>g.id===id);
 $('#group-id').textContent=group.id;$('#group-title').textContent=group.title;
 $('#status').textContent=data.statusLabels[group.status];$('#status').classList.toggle('complete',group.positive);
 expanded.clear();selectedKey=null;$('#instance').value='';locatorIndex=0;
 root=desired&&group.choices.includes(desired)?desired:group.formal;
 $('#declaration-search').value='';$('#proof-category').value='all';
 renderPicker();
 const shortcuts=[['Overview',group.formal],['General proof',group.countedGeneral||group.generals[0]],['Model application',group.countedApplication||Object.keys(group.applications)[0]]].filter(([,n])=>n);
 $('#quick-choices').innerHTML=shortcuts.map(([label,n])=>`<button data-inspect="${esc(n)}">${label}</button>`).join('');
 $('#quick-choices').querySelectorAll('[data-inspect]').forEach(b=>b.onclick=()=>b.dataset.inspect===group.formal?chooseGroup(group.id):inspect(b.dataset.inspect));
 $('#requirement-detail').innerHTML=`<p><code>${esc(group.targetName)}</code></p><p>${esc(group.target)}</p><h3>${group.positive?'Reviewed proof scope':'Current status'}</h3><p>${esc(group.clause)}</p><p>${esc(group.reason)}</p>${group.evidence.length?'<h3>Evidence for the application</h3><ul>'+group.evidence.map(p=>`<li><a href="${sourceURL({path:esc(p),line:1})}">${esc(p)}</a></li>`).join('')+'</ul>':''}${group.remaining.length?'<h3>Conditions for applying the result</h3><ul>'+group.remaining.map(x=>'<li>'+esc(typeof x==='string'?x:JSON.stringify(x))+'</li>').join('')+'</ul>':''}<p><a href="${sourceURL({path:data.registerPath,line:group.registerLine})}">Open the requirement record</a></p>`;
 renderTargets();renderGraph();if(desired)requestAnimationFrame(()=>focusNode(desired));
}
function updateHash(){
 const params=new URLSearchParams({target:activeID});if(root)params.set('theorem',root);
 history.replaceState(null,'','#'+params.toString());
}
function pathFor(points){
 if(points.length<2)return '';
 let d=`M${points[0][0]} ${points[0][1]}`;
 // Graphviz emits cubic control points, including straight polyline segments.
 for(let i=1;i+2<points.length;i+=3)d+=` C${points[i][0]} ${points[i][1]},${points[i+1][0]} ${points[i+1][1]},${points[i+2][0]} ${points[i+2][1]}`;
 return d;
}
function branchGraph(name){
 const mode=$('#definitions').checked?'data':'proof';
 const generalOnly=$('#proof-category').value==='general';
 const cacheKey=[group.id,name,mode,generalOnly].join('|');
 if(branchCache.has(cacheKey))return branchCache.get(cacheKey);
 const source=data.layouts[group.id+'|'+name+'|'+mode];
 const positions=new Map(source.nodes.map(n=>[n.id,n]));
 const allowed=n=>!generalOnly||!data.nodes[n].path.startsWith('TDN/Deployments/');
 const visited=new Set(),todo=[name];
 while(todo.length){
  const current=todo.pop();if(visited.has(current))continue;
  visited.add(current);
  source.edges.filter(e=>e.from===current&&e.to!==group.formal&&allowed(e.to)).forEach(e=>todo.push(e.to));
 }
 const nodes=source.nodes.filter(n=>visited.has(n.id));
 const edges=source.edges.filter(e=>visited.has(e.from)&&visited.has(e.to));
 const graph={nodes,edges,origin:positions.get(name)};
 branchCache.set(cacheKey,graph);return graph;
}
function buildOverview(){
 const topSource=data.layouts[group.id+'|'+group.formal+'|proof'].nodes.find(n=>n.id===group.formal);
 const names=matchingNames.filter(n=>n!==group.formal);
 const branches=names.map(name=>{
  const graph=branchGraph(name),open=expanded.has(name);
  const nodes=open?graph.nodes:[graph.origin],edges=open?graph.edges:[];
  const left=Math.min(...nodes.map(n=>n.x-n.w/2)),right=Math.max(...nodes.map(n=>n.x+n.w/2));
  return {name,nodes,edges,origin:graph.origin,left,width:right-left,expandable:graph.nodes.length>1,open};
 });
 const heights=[topSource.h];
 for(const b of branches)for(const n of b.nodes){const rank=1+n.rank-b.origin.rank;heights[rank]=Math.max(heights[rank]||0,n.h);}
 const centers=[];let y=24;
 heights.forEach((height,rank)=>{centers[rank]=y+height/2;y+=height+64;});
 const width=Math.max(topSource.w+48,branches.reduce((sum,b)=>sum+b.width,0)+Math.max(0,branches.length-1)*28+48);
 const top={...topSource,key:'specification',x:width/2,y:centers[0],rank:0,branch:false};
 const nodes=[top],edges=[];let x=24;
 for(const b of branches){
  const prefix='branch:'+b.name+'|',rankShift=1-b.origin.rank;
  const local=new Map();
  for(const n of b.nodes){
   const rank=n.rank+rankShift,placed={...n,key:prefix+n.id,x:x+n.x-b.left,y:centers[rank],rank,branch:n.id===b.name,owner:b.name,expandable:n.id===b.name&&b.expandable,open:b.open};
   nodes.push(placed);local.set(n.id,placed);
  }
  const origin=local.get(b.name),mid=(top.y+top.h/2+origin.y-origin.h/2)/2;
  const relation=group.specifications.includes(b.name)?'clause-specification':data.nodes[b.name].canonicalHead===data.nodes[group.formal].canonicalName?'proves-specification':'supports-target';
  edges.push({from:top.key,to:origin.key,kind:relation,d:`M${top.x} ${top.y+top.h/2} V${mid} H${origin.x} V${origin.y-origin.h/2}`});
  const anchors=[...new Map(b.nodes.map(n=>[n.rank,n.y])).entries()].sort((a,b)=>a[0]-b[0]).map(([rank,oldY])=>[oldY,centers[rank+rankShift]]);
  const mapY=value=>{
   if(value<=anchors[0][0])return anchors[0][1]+value-anchors[0][0];
   for(let i=1;i<anchors.length;i++)if(value<=anchors[i][0]){const [a,b]=anchors[i-1],[c,d]=anchors[i];return b+(value-a)*(d-b)/(c-a);}
   const last=anchors[anchors.length-1];return last[1]+value-last[0];
  };
  for(const e of b.edges){
   const from=local.get(e.from),to=local.get(e.to);
   const points=e.points.map(([px,py])=>[x+px-b.left,mapY(py)]);
   points[0]=[from.x,from.y+from.h/2];points[points.length-1]=[to.x,to.y-to.h/2];
   edges.push({...e,from:from.key,to:to.key,points});
  }
  x+=b.width+28;
 }
 return {top:top.key,nodes,edges,width,height:Math.max(230,y-40),branchCount:branches.length};
}
function focusNode(name){
 const node=[...$('#canvas').querySelectorAll('[data-name]')].find(el=>el.dataset.name===name&&el.dataset.branch==='true')||[...$('#canvas').querySelectorAll('[data-name]')].find(el=>el.dataset.name===name);
 if(!node)return;
 const port=$('#viewport'),a=port.getBoundingClientRect(),b=node.getBoundingClientRect();
 port.scrollLeft+=(b.left+b.right-a.left-a.right)/2;
 port.scrollTop+=b.top-a.top-55;
}
function toggleBranch(name,key){
 const before=[...$('#canvas').querySelectorAll('[data-key]')].find(el=>el.dataset.key===key)?.getBoundingClientRect();
 if(expanded.has(name))expanded.delete(name);else expanded.add(name);
 root=name;selectedKey=key;renderGraph(false);
 const after=[...$('#canvas').querySelectorAll('[data-key]')].find(el=>el.dataset.key===key)?.getBoundingClientRect();
 if(before&&after){$('#viewport').scrollLeft+=after.left-before.left;$('#viewport').scrollTop+=after.top-before.top;}
}
function renderGraph(refit=true){
 updateHash();
 if(!group.formal){
  layout=null;$('#canvas').innerHTML='';$('#canvas').hidden=true;$('#detail').hidden=true;
  $('#empty').hidden=false;$('#empty').innerHTML='<p>'+esc(group.reason)+'</p><p>No top-level proof target was selected for this RG.</p>';
  $('#graph-count').textContent='Outside the 24 selected targets';$('#selection-meaning').textContent=group.reason;
  $('#related-specification').innerHTML='';$('#collapse').disabled=true;$('#choice-count').textContent='Catalog entry; no selected proof tree.';
  $('#locator-status').textContent='Choose a selected RG to explore its declarations.';return;
 }
 $('#canvas').hidden=false;$('#detail').hidden=false;
 layout=buildOverview();
 $('#empty').hidden=layout.branchCount>0;
 $('#empty').innerHTML='<p>No related definitions or proofs match the current filters.</p>';
 $('#collapse').disabled=!expanded.size;
 $('#selection-meaning').textContent=root===group.formal?`All matching definitions and proofs appear together on the second layer. Each branch stays collapsed until you click its box.`:group.scopes[root]?`The selected theorem proves the requirement within its recorded assumptions. ${group.scopes[root]}`:root===group.countedApplication?`The selected model application checks the conditions for: ${group.clause}`:root===group.countedGeneral?`The selected general theorem establishes the following scope under its explicit assumptions: ${group.clause}`:group.applications[root]?group.applications[root]:`The selected definition or proof is associated with ${group.id}. Click its box to inspect its dependencies.`;
 renderRelatedSpecification();
 const byKey=new Map(layout.nodes.map(n=>[n.key,n]));
 let svg=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${layout.width} ${layout.height}" role="img" aria-labelledby="tree-title"><title id="tree-title">Collapsible requirement hierarchy for ${esc(group.id)}</title><defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0 L10 5 L0 10 Z" fill="var(--line)"/></marker></defs>`;
 layout.edges.forEach((e,i)=>{
  const from=byKey.get(e.from),to=byKey.get(e.to),relation=e.kind!=='dependency';
  const title=relation?`${data.nodes[to.id].name} is associated with ${data.nodes[from.id].name}; its source states the exact assumptions and conclusion`:`${data.nodes[from.id].name} uses ${data.nodes[to.id].name}`;
  svg+=`<path id="edge-${i}" class="edge ${relation?'requirement-edge':''}" d="${e.d||pathFor(e.points)}" marker-end="url(#arrow)"><title>${esc(title)}</title></path>`;
 });
 layout.nodes.forEach((p,i)=>{
  const n=data.nodes[p.id],cls=requirementSpecs.has(p.id)?'rg-spec':isProof(n)?n.kind:'definition';
  const nodeKind=requirementSpecs.has(p.id)?`${requirementSpecs.get(p.id)} top-level specification`:kindLabel(n);
  const action=p.expandable?`; click to ${p.open?'collapse':'expand'} dependencies`:'';
  const title=`${nodeKind}: ${n.name}${n.decide?'; contains a finite check':''}${action}`;
  svg+=`<g id="node-${i}" class="diagram-node ${cls}" data-name="${esc(p.id)}" data-key="${esc(p.key)}" data-branch="${!!p.branch}" data-rank="${p.rank}" role="button" tabindex="0" ${p.expandable?`aria-expanded="${p.open}"`:''} aria-label="${esc(title)}"><title>${esc(title)}</title><rect x="${p.x-p.w/2}" y="${p.y-p.h/2}" width="${p.w}" height="${p.h}" rx="7"/>`;
  if(n.decide)svg+=`<circle class="decide-marker" cx="${p.x+p.w/2-7}" cy="${p.y-p.h/2+7}" r="5"><title>Contains a finite check</title></circle>`;
  p.lines.forEach((line,j)=>{svg+=`<text x="${p.x}" y="${p.y+(j-(p.lines.length-1)/2)*15.4}" text-anchor="middle" dominant-baseline="central">${esc(line)}</text>`;});
  svg+='</g>';
 });
 $('#canvas').innerHTML=svg+'</svg>';
 $('#graph-count').textContent=`${layout.branchCount} second-layer branches; ${layout.nodes.length} visible boxes`;
 $('#canvas').querySelectorAll('[data-key]').forEach(el=>{
  const activate=()=>{const p=byKey.get(el.dataset.key);if(p.expandable)toggleBranch(p.id,p.key);else showDetail(p.id,false,p.key);};
  el.onclick=activate;el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();activate();}};
 });
 const retainedSelection=byKey.get(selectedKey);
 showDetail(retainedSelection?.id||root,false,retainedSelection?.key);renderLocator();
 if(refit)requestAnimationFrame(()=>fit(true));else setZoom(zoom,false);
}
function renderLocator(move=false){
 const query=$('#instance').value.toLowerCase().trim();
 const previous=locatorMatches[locatorIndex];
 const names=[...new Set((layout?.nodes||[]).map(n=>n.id))];
 locatorMatches=query?names.filter(name=>query.split(/\s+/).every(word=>[name,data.nodes[name].path].join(' ').toLowerCase().includes(word))):[];
 locatorIndex=previous&&locatorMatches.includes(previous)?locatorMatches.indexOf(previous):0;
 $('#locate-previous').disabled=locatorMatches.length<2;
 $('#locate-next').disabled=locatorMatches.length<2;
 if(!query){$('#locator-status').textContent='Search visible boxes by name or source file. Enter moves to the next match.';return;}
 if(!locatorMatches.length){$('#locator-status').textContent='No matching visible definitions or proofs. Change the search or tree filters.';return;}
 showLocatorMatch(move);
}
function showLocatorMatch(move){
 const name=locatorMatches[locatorIndex];if(!name)return;
 const n=data.nodes[name];
 $('#locator-status').textContent=`${locatorIndex+1} of ${locatorMatches.length}: ${n.short} — ${n.path}`;
 if(move){showDetail(name);focusNode(name);}
}
function moveLocator(direction){
 if(!locatorMatches.length)return;
 locatorIndex=(locatorIndex+direction+locatorMatches.length)%locatorMatches.length;
 showLocatorMatch(true);
}
function highlightDescendants(name,key){
 const candidates=layout?.nodes.filter(n=>n.id===name)||[];
 const anchor=candidates.find(n=>n.key===key)||candidates.find(n=>n.branch)||candidates[0];
 selectedKey=anchor?.key||null;
 const descendants=new Set(),children=new Set();
 if(anchor){
  const outgoing=new Map();
  for(const edge of layout.edges){
   if(!outgoing.has(edge.from))outgoing.set(edge.from,[]);
   outgoing.get(edge.from).push(edge.to);
   if(edge.from===anchor.key)children.add(edge.to);
  }
  const pending=[anchor.key];
  while(pending.length){const current=pending.pop();if(descendants.has(current))continue;descendants.add(current);pending.push(...(outgoing.get(current)||[]));}
 }
 const byKey=new Map((layout?.nodes||[]).map(n=>[n.key,n]));
 $('#canvas').querySelectorAll('[data-key]').forEach(el=>{
  const node=byKey.get(el.dataset.key),active=descendants.has(node.key);
  el.classList.toggle('selected',node.key===selectedKey);
  el.classList.toggle('focus-muted',!!anchor&&node.rank>anchor.rank&&!active);
  el.classList.toggle('focus-descendant',active&&node.key!==selectedKey);
  el.classList.toggle('focus-child',children.has(node.key));
 });
 for(const [i,edge] of (layout?.edges||[]).entries()){
  const el=$('#edge-'+i),active=descendants.has(edge.from)&&descendants.has(edge.to);
  el.classList.toggle('focus-muted',!!anchor&&byKey.get(edge.to).rank>anchor.rank&&!active);
  el.classList.toggle('focus-descendant',active);
 }
}
function showDetail(name,userInitiated=false,key=null){
 selected=name;const n=data.nodes[name];
 highlightDescendants(name,key);
 const input=[...new Set([...n.proofs,...n.definitions])].filter(k=>data.nodes[k]);
 const statement=n.statementDefinitions.filter(k=>k!==name&&data.nodes[k]&&!input.includes(k));
 const links=names=>names.map(k=>`<button data-detail-name="${esc(k)}">${esc(data.nodes[k].short)}</button>`).join('');
 const layer=n.path.startsWith('TDN/Models/')?'Reusable network semantics':n.path.startsWith('TDN/Requirements/')?'CSfC specifications and general proofs':'Deployments evidence, local checks, and applications';
 const certificate=group.certificates.find(c=>c.application.lean_proof===name);
 const assumptions=certificate?.implementation_contract;
 $('#detail').innerHTML=`<div class="detail-head"><div><p class="kind">${requirementSpecs.has(name)?requirementSpecs.get(name)+' top-level specification (definition)':kindLabel(n)}${n.decide?' with a finite check':''}</p><h3>${esc(n.short)}</h3><p class="source">${esc(n.path)}:${n.line}</p></div><a class="open-source" href="${sourceURL(n)}">${data.codeBase?"View on GitHub":"Open in VS Code"} ↗</a></div><p class="layer">${layer}</p><p class="meaning">${esc(n.description)}</p>${group.applications[name]?'<details><summary>Recorded application scope</summary><p>'+esc(group.scopes[name]||group.applications[name])+'</p></details>':''}${assumptions?'<details><summary>Recorded implementation assumptions</summary><ul>'+(Array.isArray(assumptions)?assumptions:[assumptions]).map(a=>'<li>'+esc(a)+'</li>').join('')+'</ul></details>':''}${input.length?'<details><summary>Direct dependencies ('+input.length+')</summary><div class="dependency-buttons">'+links(input)+'</div></details>':''}${statement.length?'<details><summary>Definitions used in the statement</summary><div class="dependency-buttons">'+links(statement)+'</div></details>':''}${n.libraries.length?'<details><summary>Direct library references</summary><p>'+n.libraries.map(x=>'<code>'+esc(x)+'</code>').join(', ')+'</p></details>':''}`;
 $('#detail').querySelectorAll('[data-detail-name]').forEach(b=>b.onclick=()=>showDetail(b.dataset.detailName,true));
 if(group.choices.includes(name)&&name!==root){
  const button=document.createElement('button');button.textContent='Locate its second-layer box';button.className='explore-item';button.onclick=()=>inspect(name);$('#detail').appendChild(button);
 }
 if(userInitiated)$('#detail').scrollIntoView({behavior:'smooth',block:'nearest'});
}
function setZoom(value,center=true){
 if(!layout)return;const port=$('#viewport');const previous=zoom;
 const cx=(port.scrollLeft+port.clientWidth/2)/previous,cy=(port.scrollTop+port.clientHeight/2)/previous;
 zoom=Math.max(.02,Math.min(2.25,value));
 const svg=$('#canvas svg');svg.style.width=`${layout.width*zoom}px`;svg.style.height=`${layout.height*zoom}px`;
 $('#canvas').style.width=`${Math.max(port.clientWidth,layout.width*zoom+40)}px`;
 $('#canvas').style.height=`${Math.max(port.clientHeight,layout.height*zoom+44)}px`;
 $('#zoom-level').textContent=Math.round(zoom*100)+'%';
 if(center){port.scrollLeft=cx*zoom-port.clientWidth/2;port.scrollTop=cy*zoom-port.clientHeight/2;}
}
function fit(readable=false){if(!layout)return;const port=$('#viewport');const widthFit=Math.min(1,(port.clientWidth-40)/layout.width);const target=readable?Math.max(.85,widthFit):widthFit;if(!document.fullscreenElement)port.style.height=Math.min(Math.max(390,innerHeight*.57),Math.max(330,layout.height*target+44))+'px';setZoom(readable?Math.max(.85,Math.min(target,(port.clientHeight-44)/layout.height)):Math.min(target,(port.clientHeight-44)/layout.height),false);port.scrollTop=0;const top=layout.nodes.find(n=>n.key===layout.top);port.scrollLeft=Math.max(0,Math.min(layout.width*zoom+40-port.clientWidth,(top?top.x:layout.width/2)*zoom+20-port.clientWidth/2));}
$('#search').oninput=renderTargets;
$('#compact-target').onchange=()=>chooseGroup($('#compact-target').value);
$('#instance').oninput=()=>{locatorMatches=[];locatorIndex=0;renderLocator(true);};
$('#instance').onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();moveLocator(e.shiftKey?-1:1);}};
$('#locate-previous').onclick=()=>moveLocator(-1);$('#locate-next').onclick=()=>moveLocator(1);
$('#declaration-search').oninput=()=>{expanded.clear();selectedKey=null;renderPicker();renderGraph();};
$('#proof-category').onchange=()=>{expanded.clear();selectedKey=null;renderPicker();renderGraph();};
$('#definitions').onchange=()=>renderGraph();
$('#collapse').onclick=()=>{expanded.clear();renderGraph();};
$('#zoom-out').onclick=()=>setZoom(zoom/1.2);$('#zoom-in').onclick=()=>setZoom(zoom*1.2);$('#fit').onclick=()=>fit();$('#actual').onclick=()=>setZoom(1);
$('#toggle-targets').onclick=()=>{const hidden=document.body.classList.toggle('targets-hidden');$('#toggle-targets').textContent=hidden?'Show targets':'Hide targets';$('#toggle-targets').setAttribute('aria-expanded',String(!hidden));requestAnimationFrame(()=>fit(true));};
$('#theme').onclick=()=>{const dark=document.documentElement.dataset.theme!=='dark';document.documentElement.dataset.theme=dark?'dark':'light';$('#theme').textContent=dark?'Light theme':'Dark theme';$('#theme').setAttribute('aria-label',`Switch to ${dark?'light':'dark'} theme`);};
$('#fullscreen').onclick=async()=>{if(document.fullscreenElement)await document.exitFullscreen();else await $('.diagram-section').requestFullscreen();fit();};
document.addEventListener('fullscreenchange',()=>{$('#fullscreen').textContent=document.fullscreenElement?'Restore':'Expand';setTimeout(fit,80);});
let drag=null;const port=$('#viewport');
port.addEventListener('pointerdown',e=>{if(e.button!==0||e.target.closest('.diagram-node'))return;drag={x:e.clientX,y:e.clientY,left:port.scrollLeft,top:port.scrollTop};port.setPointerCapture(e.pointerId);port.classList.add('dragging');});
port.addEventListener('pointermove',e=>{if(!drag)return;port.scrollLeft=drag.left+drag.x-e.clientX;port.scrollTop=drag.top+drag.y-e.clientY;});
port.addEventListener('pointerup',()=>{drag=null;port.classList.remove('dragging');});
window.addEventListener('resize',()=>{clearTimeout(window.fitTimer);window.fitTimer=setTimeout(()=>fit(true),100);});
window.addEventListener('hashchange',()=>{const p=new URLSearchParams(location.hash.slice(1));const id=p.get('target');if(data.groups.some(g=>g.id===id))chooseGroup(id,p.get('theorem'));});
chooseGroup(activeID,initial.get('theorem'));
window.hierarchyQA={data,chooseGroup,renderGraph,showDetail,fit,inspect,getLayout:()=>layout,buildOverview,branchGraph,getExpanded:()=>[...expanded]};
