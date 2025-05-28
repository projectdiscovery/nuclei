#!/usr/bin/env node

const { spawnSync } = require('node:child_process');
const esbuild = require('esbuild');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const plugin = require('node-stdlib-browser/helpers/esbuild/plugin');
const stdLibBrowser = require('node-stdlib-browser');
const util = require('node:util');
// const { nodeModulesPolyfillPlugin } = require('esbuild-plugins-node-modules-polyfill');

const NODE_LIBS_PATH = path.join(path.dirname(require.resolve(__filename)), '..', 'node_libraries');
const NPM_PREFIX = path.join(NODE_LIBS_PATH, '.modules');

const { values: args } = util.parseArgs({
  args: process.argv.slice(2),
  options: {
      "module": { type: 'string', short: 'm' },
      "import-name": { type: 'string', short: 'n' },
      "import-as": { type: 'string', short: 'a' },
      "build-platform": { type: 'string' },
      "build-target": { type: 'string' },
      "build-format": { type: 'string' },
  },
  allowPositionals: true,
});

const NPM_MODULE = args["module"] || '';
let MODULE_NAME = args["import-name"] || NPM_MODULE;
let IMPORT_AS = args["import-as"] || '';
const BUILD_PLATFORM = args["build-platform"] || 'browser';
const BUILD_TARGET = args["build-target"] || 'node10';
const BUILD_FORMAT = args["build-format"] || 'cjs';

if (!MODULE_NAME) {
  MODULE_NAME = NPM_MODULE.split('/').pop().replace(/@.*$/, '');
}

if (!NPM_MODULE || !IMPORT_AS) {
  const prog = path.basename(process.argv[1]);
  console.error(`Usage: node ${prog} --[m]odule=<module> [--[n]ame=<name>] --import-[a]s=<import-as> --build-[platform|target|format]=<value>`);
  process.exit(1);
}

IMPORT_AS = path.join(NODE_LIBS_PATH, IMPORT_AS);

if (!fs.existsSync(NODE_LIBS_PATH)) {
  console.error(`Error: Node libraries path does not exist: ${NODE_LIBS_PATH}`);
  process.exit(1);
}

if (!fs.existsSync(NPM_PREFIX)) {
  console.error(`Error: NPM prefix path does not exist: ${NPM_PREFIX}`);
  process.exit(1);
}

async function main() {
  try {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), MODULE_NAME.replace(/[^a-zA-Z0-9]/g, '-') + '-'));

    spawnSync('npm', [
      'install',
      '--prefix', NPM_PREFIX,
      '--save-dev'
    ], {
      stdio: 'inherit',
      env: { ...process.env }
    });

    spawnSync('npm', [
      'install',
      NPM_MODULE,
      '--prefix', NPM_PREFIX,
      '--save-dev'
    ], {
      stdio: 'inherit',
      env: { ...process.env }
    });

    const libPath = path.join(tempDir, 'index.js');
    const libContent = util.format(`module.exports = require(%j);`, MODULE_NAME);
    // const libContent = util.format(`try { module.exports = require(%j) } catch (e) { };`, MODULE_NAME);

    fs.writeFileSync(libPath, libContent);
    // spawnSync('bun', [
    //   'build',
    //   '--minify',
    //   '--format=cjs',
    //   '--target=browser',
    //   '--outfile', path.join(IMPORT_AS, 'index.js'),
    //   libPath
    // ], {
    //   stdio: 'inherit',
    //   env: {
    //     ...process.env,
    //     NODE_PATH: path.join(NPM_PREFIX, 'node_modules')
    //   }
    // });
    // spawnSync('browserify', [
    //   '-e', libPath,
    //   '--insert-globals',
    //   '-o', path.join(IMPORT_AS, 'index.js'),
    // ], {
    //   stdio: 'inherit',
    //   env: {
    //     ...process.env,
    //     NODE_PATH: path.join(NPM_PREFIX, 'node_modules')
    //   }
    // });
    // spawnSync('esbuild', [
    //   '--minify',
    //   '--format=cjs',
    //   '--platform=browser',
    //   '--target=node10',
    //   '--outdir=' + IMPORT_AS,
    //   '--bundle', libPath
    // ], {
    //   stdio: 'inherit',
    //   env: {
    //     ...process.env,
    //     NODE_PATH: path.join(NPM_PREFIX, 'node_modules')
    //   }
    // });

    try {
      await esbuild.build({
        entryPoints: [libPath],
        minify: true,
        bundle: true,
        platform: BUILD_PLATFORM,
        target: BUILD_TARGET,
        format: BUILD_FORMAT,
        loader: { '.js': 'jsx' },
        outfile: path.join(IMPORT_AS, 'index.js'),
        inject: [require.resolve('node-stdlib-browser/helpers/esbuild/shim')],
        define: {
          global: 'global',
          process: 'process',
          Buffer: 'Buffer'
        },
        plugins: [plugin(stdLibBrowser)],
        // plugins: [
        //   nodeModulesPolyfillPlugin({
        //     globals: {
        //       process: true,
        //       Buffer: true,
        //     },
        //   }),
        // ],
      });
    } catch (esbuildError) {
      console.log(`Removing failed module ${NPM_MODULE}...`);
      spawnSync('npm', [
        'remove',
        NPM_MODULE,
        '--prefix', NPM_PREFIX
      ], {
        stdio: 'inherit',
        env: { ...process.env }
      });
      
      throw esbuildError; // Re-throw to trigger the outer catch block
    }

    fs.rmSync(tempDir, { recursive: true });
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Unhandled error:', err);
  process.exit(1);
});
