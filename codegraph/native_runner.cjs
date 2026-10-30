#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');

function getCodeGraphModule() {
  try {
    return require('@colbymchenry/codegraph');
  } catch (e) {
    const globalPaths = [
      '/opt/homebrew/lib/node_modules/@colbymchenry/codegraph/npm-sdk.js',
      '/usr/local/lib/node_modules/@colbymchenry/codegraph/npm-sdk.js',
      '/usr/lib/node_modules/@colbymchenry/codegraph/npm-sdk.js'
    ];
    for (const p of globalPaths) {
      if (fs.existsSync(p)) return require(p);
    }
    try {
      const { execSync } = require('child_process');
      const bin = fs.realpathSync(execSync('which codegraph', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim());
      const sdk = path.join(path.dirname(bin), 'npm-sdk.js');
      if (fs.existsSync(sdk)) return require(sdk);
    } catch (_) {}
    throw e;
  }
}

const cg = getCodeGraphModule();
const cmd = process.argv[2];
const repoRoot = path.resolve(process.argv[3] || process.cwd());

if (!cg.CodeGraph.isInitialized(repoRoot)) {
  console.log(JSON.stringify({ error: "NOT_INITIALIZED" }));
  process.exit(0);
}

const graph = cg.CodeGraph.openSync(repoRoot, { readOnly: true });

if (typeof graph.getPendingReferenceCount === 'function' && graph.getPendingReferenceCount() > 0) {
  console.log(JSON.stringify({ error: "INDEX_BUILD_PENDING" }));
  try { graph.close(); } catch (_) {}
  process.exit(0);
}

if (typeof graph.getIndexState === 'function' && graph.getIndexState() === 'indexing') {
  console.log(JSON.stringify({ error: "INDEX_BUILD_PENDING" }));
  try { graph.close(); } catch (_) {}
  process.exit(0);
}

function matchesFile(nodeFilePath, fp) {
  if (!nodeFilePath || !fp) return false;
  return nodeFilePath === fp || nodeFilePath.endsWith('/' + fp) || nodeFilePath.endsWith('\\' + fp);
}

try {
  switch (cmd) {
    case 'findPath': {
      const fromSym = process.argv[4];
      const toSym = process.argv[5];
      const fromNodes = graph.getNodesByName(fromSym);
      const toNodes = graph.getNodesByName(toSym);
      if (!fromNodes.length || !toNodes.length) {
        console.log(JSON.stringify({ path: null, reason: "SYMBOL_NOT_FOUND" }));
        break;
      }
      let found = null;
      for (const fn of fromNodes) {
        for (const tn of toNodes) {
          const p = graph.findPath(fn.id, tn.id);
          if (p) { found = p; break; }
        }
        if (found) break;
      }
      console.log(JSON.stringify({ path: found }));
      break;
    }
    case 'impact': {
      const sym = process.argv[4];
      const depth = parseInt(process.argv[5] || '3', 10);
      const filePath = process.argv[6] || null;
      let seeds = (typeof graph.getNodesByName === 'function') ? graph.getNodesByName(sym) : [];
      if (filePath) {
        seeds = seeds.filter(n => matchesFile(n.filePath, filePath));
      }
      if (!seeds.length) {
        console.log(JSON.stringify({ roots: [], results: [] }));
        break;
      }
      const CONTAINER_KINDS = new Set(['class', 'interface', 'struct', 'module', 'namespace', 'file']);
      const seen = new Set(seeds.map(n => n.id));
      const queue = seeds.map(n => ({ id: n.id, hop: 0 }));
      // Expand container seeds at hop 0 so callers of member methods appear in impact
      for (const seed of [...seeds]) {
        if (CONTAINER_KINDS.has(seed.kind)) {
          const children = (typeof graph.getChildren === 'function') ? graph.getChildren(seed.id) : [];
          for (const child of children) {
            if (!seen.has(child.id)) {
              seen.add(child.id);
              queue.push({ id: child.id, hop: 0 });
            }
          }
        }
      }
      const results = [];

      while (queue.length > 0) {
        const { id, hop } = queue.shift();
        if (hop >= depth) continue;
        const incoming = (typeof graph.getIncomingEdgesTo === 'function') ? graph.getIncomingEdgesTo([id]) : [];
        incoming.sort((a, b) => ((a.line || 0) - (b.line || 0)));
        for (const e of incoming) {
          if (e.kind === 'contains') continue;
          const src = typeof graph.getNode === 'function' ? graph.getNode(e.source) : null;
          if (!src || seen.has(src.id)) continue;
          seen.add(src.id);
          const conf = (e.metadata && typeof e.metadata.confidence === 'number') ? e.metadata.confidence : 1.0;
          results.push({
            node: { id: src.id, name: src.name, kind: src.kind, filePath: src.filePath, startLine: src.startLine },
            hop: hop + 1,
            kind: e.kind,
            confidence: conf,
            viaLine: e.line || src.startLine
          });
          queue.push({ id: src.id, hop: hop + 1 });
          if (CONTAINER_KINDS.has(src.kind)) {
            const children = (typeof graph.getChildren === 'function') ? graph.getChildren(src.id) : [];
            for (const child of children) {
              if (seen.has(child.id)) continue;
              seen.add(child.id);
              results.push({
                node: { id: child.id, name: child.name, kind: child.kind, filePath: child.filePath, startLine: child.startLine },
                hop: hop + 1,
                kind: 'contains',
                confidence: 1.0,
                viaLine: child.startLine
              });
              queue.push({ id: child.id, hop: hop + 1 });
            }
          }
        }
      }

      console.log(JSON.stringify({
        roots: seeds.map(n => ({ id: n.id, name: n.name, kind: n.kind, filePath: n.filePath, startLine: n.startLine })),
        nodes: results.map(r => r.node),
        results
      }));
      break;
    }
    case 'routingManifest': {
      let manifest = graph.getRoutingManifest();
      const frameworks = graph.getDetectedFrameworks();
      const entries = (manifest && manifest.entries) ? manifest.entries : [];
      if (!entries || entries.length === 0) {
        const routeNodes = typeof graph.getNodesByKind === 'function' ? graph.getNodesByKind('route') : [];
        if (routeNodes && routeNodes.length > 0) {
          const fallbackEntries = [];
          for (const r of routeNodes) {
            const edges = typeof graph.getOutgoingEdgesFrom === 'function'
              ? graph.getOutgoingEdgesFrom([r.id], ['references', 'calls'])
              : [];
            let handlerName = 'handler';
            let handlerFile = r.filePath;
            let handlerLine = r.startLine;
            let handlerKind = 'function';
            if (edges && edges.length > 0) {
              const targetNode = typeof graph.getNode === 'function' ? graph.getNode(edges[0].target) : null;
              if (targetNode) {
                handlerName = targetNode.name || handlerName;
                handlerFile = targetNode.filePath || handlerFile;
                handlerLine = targetNode.startLine || handlerLine;
                handlerKind = targetNode.kind || handlerKind;
              }
            }
            if (handlerFile) {
              const fileObj = typeof graph.getFile === 'function' ? graph.getFile(handlerFile) : null;
              if (fileObj && fileObj.generated) {
                continue;
              }
            }
            fallbackEntries.push({
              url: r.name,
              handler: handlerName,
              handlerFile: handlerFile,
              handlerLine: handlerLine,
              handlerKind: handlerKind,
              routeId: r.id,
              routeFile: r.filePath,
              routeLine: r.startLine
            });
          }
          manifest = { entries: fallbackEntries, totalRoutes: fallbackEntries.length };
        }
      }
      console.log(JSON.stringify({ manifest, frameworks }));
      break;
    }
    case 'circularAndDead': {
      const circular = graph.findCircularDependencies();
      const dead = graph.findDeadCode();
      console.log(JSON.stringify({
        circular,
        dead: dead.slice(0, 50).map(n => ({
          id: n.id,
          name: n.name,
          kind: n.kind,
          filePath: n.filePath,
          startLine: n.startLine
        }))
      }));
      break;
    }
    case 'typeHierarchy': {
      const sym = process.argv[4];
      const matches = graph.getNodesByName(sym);
      const focal = matches.find(n => n.kind === 'class' || n.kind === 'interface') || matches[0];
      if (!focal) {
        console.log(JSON.stringify({ symbol: sym, nodes: [], edges: [] }));
        break;
      }
      const nodes = new Map([[focal.id, focal]]);
      const edges = [];
      const seen = new Set();
      const walk = (dir) => {
        const visited = new Set([focal.id]);
        let frontier = [focal.id];
        while (frontier.length) {
          const next = [];
          for (const id of frontier) {
            const adj = (dir === 'up' ? graph.getOutgoingEdges(id) : graph.getIncomingEdges(id))
              .filter(e => e.kind === 'extends' || e.kind === 'implements');
            for (const e of adj) {
              const other = dir === 'up' ? e.target : e.source;
              const k = `${e.source}->${e.target}:${e.kind}`;
              if (!seen.has(k)) { seen.add(k); edges.push(e); }
              if (!visited.has(other)) {
                visited.add(other);
                next.push(other);
                const n = graph.getNode(other);
                if (n && !nodes.has(n.id)) nodes.set(n.id, n);
              }
            }
          }
          frontier = next;
        }
      };
      walk('up');
      walk('down');
      console.log(JSON.stringify({
        symbol: sym,
        nodes: Array.from(nodes.values()).map(n => ({
          id: n.id,
          name: n.name,
          kind: n.kind,
          filePath: n.filePath,
          startLine: n.startLine,
          endLine: n.endLine
        })),
        edges
      }));
      break;
    }
    case 'callers': {
      const sym = process.argv[4];
      const limit = parseInt(process.argv[5] || '100', 10);
      const sliceLimit = limit > 0 ? limit : undefined;
      const filePath = process.argv[6] || null;
      let nodes = (typeof graph.getNodesByName === 'function') ? graph.getNodesByName(sym) : [];
      if (filePath) {
        nodes = nodes.filter(n => matchesFile(n.filePath, filePath));
      }
      const definitions = [];
      const callersList = [];
      const seenCalls = new Set();

      for (const n of nodes) {
        definitions.push({
          id: n.id,
          name: n.name,
          kind: n.kind,
          filePath: n.filePath,
          startLine: n.startLine,
          signature: n.signature
        });
        const callers = (typeof graph.getCallers === 'function') ? graph.getCallers(n.id) : [];
        for (const c of callers) {
          if (c.edge && c.edge.kind && c.edge.kind !== 'calls') continue;
          const callLine = (c.edge && c.edge.line) ? c.edge.line : c.node.startLine;
          const key = `${c.node.filePath}:${callLine}`;
          if (seenCalls.has(key)) continue;
          seenCalls.add(key);
          callersList.push({
            id: c.node.id,
            name: c.node.name,
            kind: c.node.kind,
            filePath: c.node.filePath,
            line: callLine,
            edgeKind: c.edge ? c.edge.kind : 'calls',
            confidence: (c.edge && c.edge.metadata && typeof c.edge.metadata.confidence === 'number') ? c.edge.metadata.confidence : 1.0
          });
        }
      }
      console.log(JSON.stringify({
        symbol: sym,
        definitions: definitions.slice(0, sliceLimit),
        callers: callersList.slice(0, sliceLimit)
      }));
      break;
    }
    case 'callees': {
      const sym = process.argv[4];
      const limit = parseInt(process.argv[5] || '100', 10);
      const sliceLimit = limit > 0 ? limit : undefined;
      const filePath = process.argv[6] || null;
      let nodes = (typeof graph.getNodesByName === 'function') ? graph.getNodesByName(sym) : [];
      if (filePath) {
        nodes = nodes.filter(n => matchesFile(n.filePath, filePath));
      }
      const calleesList = [];
      const seenCallees = new Set();

      for (const n of nodes) {
        const callees = (typeof graph.getCallees === 'function') ? graph.getCallees(n.id) : [];
        for (const c of callees) {
          const key = `${c.node.filePath}:${c.node.name}()`;
          if (seenCallees.has(key)) continue;
          seenCallees.add(key);
          calleesList.push({
            id: c.node.id,
            name: c.node.name,
            kind: c.node.kind,
            filePath: c.node.filePath,
            startLine: c.node.startLine,
            label: key
          });
        }
      }
      console.log(JSON.stringify({
        symbol: sym,
        callees: calleesList.slice(0, sliceLimit)
      }));
      break;
    }
    case 'fileDependencies': {
      const pairs = typeof graph.getFileDependencyPairs === 'function'
        ? graph.getFileDependencyPairs()
        : [];
      console.log(JSON.stringify({ pairs }));
      break;
    }
    case 'context': {
      const task = process.argv[4];
      const maxNodes = parseInt(process.argv[5] || '20', 10);
      graph.buildContext(task, { maxNodes, includeCode: false, format: 'json' })
        .then(res => {
          const parsed = typeof res === 'string' ? JSON.parse(res) : res;
          console.log(JSON.stringify(parsed));
          try { graph.close(); } catch (_) {}
        })
        .catch(err => {
          console.log(JSON.stringify({ error: String(err) }));
          try { graph.close(); } catch (_) {}
        });
      return;
    }
    default:
      console.log(JSON.stringify({ error: `UNKNOWN_COMMAND: ${cmd}` }));
  }
} catch (err) {
  console.log(JSON.stringify({ error: String(err) }));
} finally {
  try {
    graph.close();
  } catch (_) {}
}
