# Research round — 2026-09-06: how AI agents talk to each other

A source-code pass over the protocols and SDKs that agents use to reach
tools, hosts, and other agents. Every claim below was checked against the
schema or source file linked in the Sources section, not against blog
posts. Nothing here changes LTP yet. The backlog at the end lists where
LTP could plug in.

## Summary

Agents talk at four layers. Each layer has one dominant wire shape.

| Layer | Who talks to whom | Dominant shape | Standard or SDK |
|---|---|---|---|
| In-process | Agents inside one runtime | A tool call named "transfer" or "delegate", or a graph edge | OpenAI Agents SDK, CrewAI, Google ADK, LangGraph, AutoGen, Claude Agent SDK |
| Agent to tool | An agent and a capability server | JSON-RPC 2.0 over stdio or Streamable HTTP | MCP (Model Context Protocol) |
| Agent to agent over a network | Two independent agents, possibly different vendors | JSON-RPC 2.0, gRPC, or REST, with a discovery card | A2A (Agent2Agent) 1.0 |
| Host to agent | An editor or IDE and a coding agent | JSON-RPC 2.0 over stdio | ACP (Agent Client Protocol, Zed) |

Six patterns repeat across all four layers:

1. **JSON-RPC 2.0 is the envelope** on every network wire (MCP, A2A's
   primary binding, ACP).
2. **Capabilities are negotiated up front.** MCP and ACP do it in
   `initialize`. A2A does it with a published Agent Card.
3. **Streaming is Server-Sent Events.** MCP Streamable HTTP and A2A both
   use SSE for partial results.
4. **Multi-turn work has an id.** MCP has a session id header. A2A has
   `taskId` and `contextId`. ACP has a session id.
5. **Humans stay in the loop through the protocol.** MCP has
   `elicitation/create`. A2A has `INPUT_REQUIRED` and `AUTH_REQUIRED`
   states. ACP has `session/request_permission`.
6. **In-process delegation is just a tool.** Every SDK exposes "hand off
   to agent X" as a function the model can call.

## Layer 1: in-process, one runtime

| SDK | Mechanism | What crosses the boundary |
|---|---|---|
| OpenAI Agents SDK | A `Handoff` is a tool. Default name is `transfer_to_<agent name>`. | Whole conversation history, optionally trimmed by `input_filter` |
| CrewAI | A tool called "Delegate work to coworker" with `task`, `context`, `coworker` | Free text task and context |
| Google ADK | A function tool `transfer_to_agent(agent_name, tool_context)` | Control transfers; shared session state stays |
| LangGraph | `Command(goto=..., update=..., graph=Command.PARENT)` and `Send(node, arg)` | A state update plus a routing target |
| AutoGen core | Actor model. `send_message(message, recipient: AgentId)` for request-reply. `publish_message(message, topic_id)` for pub/sub. | Any Python object, typed by the handler |
| Claude Agent SDK and Claude Code | Subagents declared as `AgentDefinition` (description, prompt, tools, model, MCP servers). Messages carry `senderTaskId` for in-process subagents and `fromSession` for cross-session peers. | Text body plus sender identity |

Take-away: inside one process, "agent-to-agent" is not a protocol. It is a
function call with a conversation attached. The model decides to call it.

## Layer 2: agent to tool, MCP

Protocol version `2025-06-18`. JSON-RPC 2.0.

- **Transports.** `stdio` (client launches the server as a child process)
  and **Streamable HTTP** (one endpoint, client POSTs, server may reply
  with SSE). Custom transports are allowed.
- **Client-to-server methods.** `initialize`, `ping`, `tools/list`,
  `tools/call`, `resources/list`, `resources/read`,
  `resources/templates/list`, `resources/subscribe`,
  `resources/unsubscribe`, `prompts/list`, `prompts/get`,
  `completion/complete`, `logging/setLevel`.
- **Server-to-client methods.** `sampling/createMessage` (the server asks
  the client's model to generate text), `elicitation/create` (the server
  asks the user a question), `roots/list`.
- **Notifications.** `initialized`, `cancelled`, `progress`, `message`,
  and `*/list_changed` for tools, prompts, resources, and roots.

Take-away: MCP is how an agent *uses* something. A2A's own spec says so in
its Appendix B. An agent can be wrapped as an MCP tool, but MCP has no
notion of a long-running task owned by a peer.

## Layer 3: agent to agent over a network, A2A

Version 1.0. Three bindings with one data model.

- **Discovery.** `GET /.well-known/agent-card.json` returns an
  `AgentCard`: name, description, skills (`AgentSkill`), capabilities
  (streaming, push notifications, extensions), interfaces
  (`AgentInterface` per binding), and security schemes. Cards may be
  signed with JWS (RFC 7515). An authenticated call to
  `GetExtendedAgentCard` can return more skills than the public card.
- **Operations.** `SendMessage`, `SendStreamingMessage`, `GetTask`,
  `ListTasks`, `CancelTask`, `SubscribeToTask`, create/get/list/delete
  push-notification config, `GetExtendedAgentCard`.
- **Bindings.** JSON-RPC 2.0 over HTTP with SSE for streams; gRPC; and
  HTTP+JSON/REST (for example `POST /message:stream`). The
  `A2A-Version` header carries the protocol version.
- **Data model.** `Task` holds status and history. `Message` has a role
  and a list of `Part`s. A `Part` is `TextPart`, `FilePart` (bytes or a
  URI), or `DataPart` (structured JSON). Agents return results as
  `Artifact`s. Streaming sends `TaskStatusUpdateEvent` and
  `TaskArtifactUpdateEvent`.
- **Task states.** `SUBMITTED`, `WORKING`, `INPUT_REQUIRED`,
  `AUTH_REQUIRED`, `COMPLETED`, `CANCELED`, `FAILED`, `REJECTED`.
- **Multi-turn.** `contextId` groups tasks into one conversation. A message
  with a `contextId` but no `taskId` starts a new task in that
  conversation. Mismatched ids must be rejected. `referenceTaskIds`
  points at related tasks.
- **Reference client.** The `a2a-python` client exposes one method per
  operation, so the wire and the SDK match one to one. Google ADK ships an
  `A2aAgentExecutor` that serves an ADK agent over A2A.

Take-away: A2A is the only layer where two agents are peers with a shared,
inspectable task lifecycle and a signed identity document.

## Layer 4: host to agent, ACP

Zed's Agent Client Protocol. Stable protocol version 1, negotiated in
`initialize`. JSON-RPC 2.0 over stdio.

- **Agent methods.** `initialize`, `authenticate`, `session/new`,
  `session/load`, `session/resume`, `session/list`, `session/prompt`,
  `session/cancel`, `session/close`, `session/delete`,
  `session/set_mode`, `session/set_config_option`.
- **Client methods the agent calls back.** `session/update` (progress),
  `session/request_permission`, `fs/read_text_file`,
  `fs/write_text_file`, `terminal/create`, `terminal/output`,
  `terminal/wait_for_exit`, `terminal/kill`, `terminal/release`.

Take-away: the host owns the filesystem and terminal. The agent asks for
them. This is the same permission shape Claude Code uses with its own
harness.

## Where LTP could plug in

Ordered by leverage. None of these is scheduled.

1. **Anchor an A2A `Artifact`.** A2A has no integrity anchor. An agent
   that returns a `FilePart` by URI gives the caller no way to prove the
   bytes later. An LTP anchor bound to the `taskId` and artifact id would
   give a verifiable receipt. Needs a Linear ticket before any wire-format
   work; see `AGENTS.md` Boundaries.
2. **Expose LTP as an MCP server.** `tools/call` over `src/ltp` (commit,
   lattice, materialize, verify) would let any MCP-capable agent use LTP
   without an SDK. Read-only first.
3. **Publish an Agent Card for a corridor super-node.** Skills would be
   "attest state root" and "verify anchor". The card's JWS signature is a
   natural place to reuse the node's existing key material.

## Sources

All fetched on 2026-09-06 from the default branch unless noted.

- A2A spec: https://github.com/a2aproject/A2A/blob/main/docs/specification.md
- A2A Python client: https://github.com/a2aproject/a2a-python/blob/main/src/a2a/client/client.py
- MCP schema: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2025-06-18/schema.ts
- MCP transports: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2025-06-18/basic/transports.mdx
- ACP schema v1: https://github.com/agentclientprotocol/agent-client-protocol/blob/main/schema/v1/schema.json
- OpenAI Agents SDK handoffs: https://github.com/openai/openai-agents-python/blob/main/src/agents/handoffs/__init__.py
- CrewAI delegation tool: https://github.com/crewAIInc/crewAI/blob/main/lib/crewai/src/crewai/tools/agent_tools/delegate_work_tool.py
- Google ADK transfer tool: https://github.com/google/adk-python/blob/main/src/google/adk/tools/transfer_to_agent_tool.py
- Google ADK A2A executor: https://github.com/google/adk-python/blob/main/src/google/adk/a2a/executor/a2a_agent_executor.py
- LangGraph `Command` and `Send`: https://github.com/langchain-ai/langgraph/blob/main/libs/langgraph/langgraph/types.py
- AutoGen core runtime: https://github.com/microsoft/autogen/blob/main/python/packages/autogen-core/src/autogen_core/_agent_runtime.py
- Claude Agent SDK types: https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/types.py
