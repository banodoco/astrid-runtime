import { DirectHarness, PRODUCT_ACTOR } from './support/harness.ts';
import { AstridCli } from './support/astrid.ts';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { seedOneClip } from './p1-seed.ts';

const [root, capture, mode] = process.argv.slice(2);
const h: any = new DirectHarness();
h.tmp = path.join(root, 'fixture');
mkdirSync(h.tmp, { recursive: true });
mkdirSync(h.supportDir, { recursive: true });
h.origin = 'https://astrid.test:38443';
h.doorPort = Number(process.env.READINESS_DOOR_PORT);
function state(stage: string) {
  writeFileSync(path.join(root, 'state.json'), JSON.stringify({ stage,
    endpoint: h.runtimeUrl, door: h.doorBase, origin: h.origin,
    project: h.seed?.projectId, timeline: h.seed?.timelineId,
    credential: h.credentialPath, daemonPid: h.runtime?.child.pid,
  }));
}
async function wait(name: string) {
  const deadline = Date.now() + 180_000;
  while (!existsSync(path.join(root, name))) {
    if (Date.now() > deadline) throw new Error('probe handshake deadline');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}
try {
  h.realmId = await h.createRealm();
  await h.startRuntime();
  h.productToken = await h.provisionCredential(PRODUCT_ACTOR, path.basename(h.credentialPath));
  h.seed = await h.seedRuntime(true);
  state('baseline');
  await wait('GO');
  state('writer');
  if (mode === 'p1') {
    const astrid = await AstridCli.create(h);
    const seed = await seedOneClip(h, astrid);
    h.seed.timelineId = seed.timelineId;
  } else {
    await h.seedThreeProducts();
  }
  state('idle');
  await wait('STOP');
} catch (error) {
  // Raw failure detail stays in private scratch for inspection and redaction.
  writeFileSync(path.join(root, 'error.txt'), String(error) + '\n' + (error as Error).stack);
  state('error');
  process.exitCode = 1;
} finally {
  if (h.runtime) {
    writeFileSync(path.join(root, 'daemon-stdout.txt'), h.runtime.stdout);
    writeFileSync(path.join(root, 'daemon-stderr.txt'), h.runtime.stderr);
  }
  await h.stopRuntime();
}
