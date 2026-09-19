import { createApplication } from './app.js';
import { loadConfig } from './config.js';

async function main(): Promise<void> {
  const runtime = loadConfig();
  const { app } = await createApplication(runtime);
  app.listen(runtime.uiPort, '0.0.0.0', () => {
    console.log(`AWG Panel запущена на порту ${runtime.uiPort}; AWG ${runtime.portable.version}`);
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
