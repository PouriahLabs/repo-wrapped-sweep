import { main } from "./cli";

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`sweep failed: ${(err as Error).message}\n`);
    process.exitCode = 2;
  },
);
