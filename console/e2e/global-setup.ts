import path from "node:path";
import { resetBank, startAgent, startStack, stackIsUp } from "./support/stack";

/**
 * Before the browser: make sure the compose stack is up, put the bank at its seed state and start
 * the agent whose transfer the test approves. The transcript path goes to the test through the
 * environment. What the function returns runs after the last test and stops an agent that is
 * still waiting, which it would do for two minutes if the test failed before approving.
 */
export default async function globalSetup(): Promise<() => void> {
  if (!(await stackIsUp())) {
    startStack();
    if (!(await stackIsUp())) throw new Error("the stack started but is not answering");
  }
  await resetBank();

  const transcript = path.join(import.meta.dirname, "..", "test-results", "approval-agent.txt");
  const agent = startAgent(transcript);
  process.env["KS_E2E_TRANSCRIPT"] = transcript;

  return () => {
    if (agent.child.exitCode === null) agent.child.kill("SIGTERM");
  };
}
