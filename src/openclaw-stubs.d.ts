// Type stubs for the openclaw plugin SDK (provided at runtime, not installed as a package)
declare module "openclaw/plugin-sdk/plugin-entry" {
  export interface MessageReceivedEvent {
    message: string;
  }

  export interface BeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
  }

  export interface LlmInputEvent {
    messages: unknown[];
  }

  export type HookEvent = MessageReceivedEvent | BeforeToolCallEvent | LlmInputEvent;

  export interface HookResult {
    block?: boolean;
    blockReason?: string;
  }

  export interface CommandContext {
    sessionId?: string;
  }

  export interface CommandDefinition<TParams extends Record<string, unknown>> {
    name: string;
    description: string;
    parameters: unknown;
    execute: (ctx: CommandContext, params: TParams) => Promise<string> | string;
  }

  export interface Logger {
    debug(msg: string, ...args: unknown[]): void;
    info(msg: string, ...args: unknown[]): void;
    warn(msg: string, ...args: unknown[]): void;
    error(msg: string, ...args: unknown[]): void;
  }

  export interface RuntimeState {
    resolveStateDir(): string;
  }

  export interface RuntimeConfig {
    loadConfig(): Promise<unknown>;
    writeConfigFile(cfg: unknown): Promise<void>;
  }

  export interface Runtime {
    state: RuntimeState;
    config: RuntimeConfig;
  }

  export interface PluginApi {
    pluginConfig: Record<string, unknown>;
    logger: Logger;
    runtime: Runtime;
    registerHook(
      event: "message_received",
      handler: (event: MessageReceivedEvent, ctx: unknown) => Promise<HookResult | void> | HookResult | void,
    ): void;
    registerHook(
      event: "before_tool_call",
      handler: (event: BeforeToolCallEvent, ctx: unknown) => Promise<HookResult | void> | HookResult | void,
    ): void;
    registerHook(
      event: "llm_input",
      handler: (event: LlmInputEvent, ctx: unknown) => Promise<HookResult | void> | HookResult | void,
    ): void;
    registerCommand<TParams extends Record<string, unknown>>(
      def: CommandDefinition<TParams>,
    ): void;
  }

  export type PluginRegisterFn = (api: PluginApi) => void | Promise<void>;

  export function definePluginEntry(fn: PluginRegisterFn): PluginRegisterFn;
}
