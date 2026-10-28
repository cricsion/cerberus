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
    case 'callGraph': {
      const sym = process.argv[4];
      const depth = parseInt(process.argv[5] || '2', 10);
      const nodes = graph.getNodesByName(sym);
      if (!nodes.length) {
        console.log(JSON.stringify({ nodes: [], edges: [] }));
        break;
      }
      const cgRes = graph.getCallGraph(nodes[0].id, depth);
      const nodesList = cgRes.nodes ? Array.from(cgRes.nodes.values()) : [];
      console.log(JSON.stringify({
        edges: cgRes.edges || [],
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
    case 'typeHierarchy': {
      const sym = process.argv[4];
      const nodes = graph.getNodesByName(sym);
      if (!nodes.length) {
        console.log(JSON.stringify({ nodes: [], edges: [] }));
        break;
      }
      const th = graph.getTypeHierarchy(nodes[0].id);
      const nodesList = th.nodes ? Array.from(th.nodes.values()) : [];
      console.log(JSON.stringify({
        edges: th.edges || [],
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
    case 'metrics': {
      const sym = process.argv[4];
      const nodes = graph.getNodesByName(sym);
      if (!nodes.length) {
        console.log(JSON.stringify({ metrics: null }));
        break;
      }
      const metrics = graph.getNodeMetrics(nodes[0].id);
      console.log(JSON.stringify({ metrics }));
      break;
    }
    case 'usages': {
      const sym = process.argv[4];
      const nodes = graph.getNodesByName(sym);
      if (!nodes.length) {
        console.log(JSON.stringify({ usages: [] }));
        break;
      }
      const usages = graph.findUsages(nodes[0].id);
      console.log(JSON.stringify({
        symbol: sym,
        usages: usages.slice(0, 100).map(u => ({
          node: {
            id: u.node.id,
            name: u.node.name,
            kind: u.node.kind,
            filePath: u.node.filePath,
            startLine: u.node.startLine
          },
          edge: {
            kind: u.edge.kind,
            source: u.edge.source,
            target: u.edge.target
          }
        }))
      }));
      break;
    }
    case 'context': {
      const sym = process.argv[4];
      const nodes = graph.getNodesByName(sym);
      if (!nodes.length) {
        console.log(JSON.stringify({ context: null }));
        break;
      }
      const ctx = graph.getContext(nodes[0].id);
      console.log(JSON.stringify({ context: ctx }));
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
