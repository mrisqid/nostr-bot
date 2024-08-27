import { startService, stopService } from "../src/index.ts";

const service = await startService();

process.on("SIGINT", () => {
  stopService(service);
  process.exit(0);
});
