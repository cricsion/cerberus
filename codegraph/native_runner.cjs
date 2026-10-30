#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');

function getCodeGraphModule() {
  try {
    return require('@colbymchenry/codegraph');
  } catch (e) {
    const { execSync } = require('child_process');
    try {
      const bin = fs.realpathSync(execSync('which codegraph', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim());
      const sdk = path.join(path.dirname(bin), 'npm-sdk.js');
      if (fs.existsSync(sdk)) return require(sdk);
    } catch (_) {}

    try {
      const npmRoot = execSync('npm root -g', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }).trim();
      const sdk = path.join(npmRoot, '@colbymchenry/codegraph', 'npm-sdk.js');
      if (fs.existsSync(sdk)) return require(sdk);
    } catch (_) {}

    const globalPaths = [
      '/opt/homebrew/lib/node_modules/@colbymchenry/codegraph/npm-sdk.js',
      '/usr/local/lib/node_modules/@colbymchenry/codegraph/npm-sdk.js',
      '/usr/lib/node_modules/@colbymchenry/codegraph/npm-sdk.js'
    ];
    for (const p of globalPaths) {
      if (fs.existsSync(p)) return require(p);
    }
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
      const depth = parseInt(process.argv[5] || '2', 10);
      const nodes = graph.getNodesByName(sym);
      if (!nodes.length) {
        console.log(JSON.stringify({ nodes: [], edges: [], roots: [] }));
        break;
      }
      const impact = graph.getImpactRadius(nodes[0].id, depth);
      const nodesList = impact.nodes ? Array.from(impact.nodes.values()) : [];
      console.log(JSON.stringify({
        roots: impact.roots,
        edges: impact.edges,
        nodes: nodesList.map(n => ({
          id: n.id,
          name: n.name,
          kind: n.kind,
          filePath: n.filePath,
          startLine: n.startLine,
          endLine: n.endLine
        }))
      }));
      break;
    }
    case 'routingManifest': {
      const manifest = graph.getRoutingManifest();
      const frameworks = graph.getDetectedFrameworks();
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
      const typeKinds = new Set([
        'class', 'interface', 'struct', 'trait', 'enum', 'union',
        'type', 'record', 'protocol', 'impl'
      ]);
      const matches = graph.getNodesByName(sym);
      const focal = matches.find(n => typeKinds.has(n.kind)) || matches[0];
      if (!focal) {
        console.log(JSON.stringify({ symbol: sym, nodes: [], edges: [] }));
        break;
      }

      const nodes = new Map([[focal.id, focal]]);
      const edges = [];
      const seen = new Set();
      const maxNodes = 256;

      const walk = (direction) => {
        const visited = new Set([focal.id]);
        let frontier = [focal.id];
        while (frontier.length && nodes.size < maxNodes) {
          const next = [];
          for (const id of frontier) {
            const adjacent = direction === 'up'
              ? graph.getOutgoingEdges(id)
              : graph.getIncomingEdges(id);
            for (const edge of adjacent) {
              if (edge.kind !== 'extends' && edge.kind !== 'implements') continue;
              const other = direction === 'up' ? edge.target : edge.source;
              const key = JSON.stringify([edge.source, edge.target, edge.kind, edge.line, edge.column]);
              if (!seen.has(key)) {
                seen.add(key);
                edges.push(edge);
              }
              if (!visited.has(other)) {
                visited.add(other);
                next.push(other);
              }
            }
          }
          if (next.length) {
            const fetched = graph.getNodesByIds(next);
            for (const [id, node] of fetched) {
              if (nodes.size >= maxNodes) break;
              if (!nodes.has(id)) nodes.set(id, node);
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
