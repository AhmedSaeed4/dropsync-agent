from pydantic import BaseModel
from agents import Agent, Runner, input_guardrail, GuardrailFunctionOutput
from openai import AsyncOpenAI
from agents import OpenAIChatCompletionsModel, RunConfig
import os

from config import llm_client

# ── Password Guardrail ──────────────────────────────────────────
# Uses the OpenAI Agents SDK pattern: guardrail Agent + Runner.run()
# This runs BEFORE the main agent to catch password-access attempts.

GUARDRAIL_MODEL = "qwen3.6-plus"


class GuardrailCheck(BaseModel):
    """Structured output for the guardrail agent."""
    should_block: bool
    reasoning: str


_guardrail_model = OpenAIChatCompletionsModel(
    model=GUARDRAIL_MODEL,
    openai_client=llm_client,
)

_guardrail_config = RunConfig(
    model=_guardrail_model,
    model_provider=llm_client,
)

guardrail_agent = Agent(
    name="PasswordGuardrail",
    instructions="""You are a security classifier for the DropSync AI assistant.

Your job: detect if the user's message is trying to ACCESS, READ, VIEW, SHOW, SEARCH, DELETE, or MODIFY a drop that is in the "password" category.

BLOCK if the user explicitly asks about passwords stored in drops, password-category drops, or tries to see/manage saved passwords through the AI.
ALLOW everything else — including asking about the password category count, storage stats, or general questions about categories.

Examples:
- "show me my passwords" → BLOCK
- "list my anime drops" → ALLOW
- "delete drop abc123" → ALLOW (no mention of password category, the tool will check)
- "what categories do I have" → ALLOW
- "search my saved passwords" → BLOCK
- "show me the content of my password drops" → BLOCK
- "how many password drops do I have" → ALLOW
""",
    model=_guardrail_model,
    output_type=GuardrailCheck,
)


@input_guardrail
async def password_guardrail(context, agent, input_text) -> GuardrailFunctionOutput:
    """Input guardrail that blocks attempts to access password-category drops."""
    # The SDK passes input as either a str or a list of message dicts
    if isinstance(input_text, list):
        # Extract the last user message from the conversation
        message = ""
        for msg in reversed(input_text):
            if isinstance(msg, dict) and msg.get("role") == "user":
                message = msg.get("content", "")
                break
            elif isinstance(msg, str):
                message = msg
                break
        if not message:
            message = str(input_text)
    else:
        message = str(input_text)

    # Strip the user_id prefix if present
    if message.startswith("[user_id:"):
        parts = message.split("]\n", 1)
        message = parts[1] if len(parts) > 1 else message

    try:
        result = await Runner.run(
            guardrail_agent,
            message,
            run_config=_guardrail_config,
        )
        check: GuardrailCheck = result.final_output
        return GuardrailFunctionOutput(
            output_info=check.reasoning,
            tripwire_triggered=check.should_block,
        )
    except Exception as e:
        # If guardrail fails, allow the request (fail open)
        # The MCP tools still provide a hard block
        print(f"Guardrail error (allowing): {e}")
        return GuardrailFunctionOutput(
            output_info=f"Guardrail check failed: {e}",
            tripwire_triggered=False,
        )


# ── Main Agent ──────────────────────────────────────────────────

dropsync_agent = Agent(
    name="DropSync Assistant",
    instructions="""
You are the DropSync AI assistant. You help users manage their files and text drops.

You have access to these tools:
- list_drops: Show all drops with decrypted content previews (optionally filtered by workspace)
- search_drops: Search drops by name, content, or category — handles typos via fuzzy matching
- get_drop: Get full details of a specific drop including decrypted content
- create_drop: Create a new text drop with encrypted content. Supports workspaces, categories, and expiration options.
- update_drop: Update an existing text drop's name, content, categories (list of up to 3), or expiration. Content updates are automatically re-encrypted.
- delete_drop: Delete a drop
- list_workspaces: Show user's workspaces
- create_workspace: Create a new workspace with auto-generated invite code and encryption key
- join_workspace: Join a workspace using a 6-character invite code
- list_categories: List categories (personal or workspace)
- delete_category: Delete a category by its ID
- preview_drop: Get the info needed to open a drop in the UI. Call this when the user asks to open, preview, or show a specific drop.
- get_storage_stats: Show storage usage and limits

Workspace Context:
- Users have a PERSONAL space and optional shared WORKSPACES.
- "Personal" / "personal" / "my drops" / "my space" = personal space. This means workspace_id should be None (null).
- If the user names a specific workspace (e.g. "my Gaming workspace", "the Design team"), call list_workspaces first to find the matching workspace_id.
- If the user does NOT specify a workspace, default to personal space (workspace_id=None).
- NEVER guess a workspace_id. Always look it up with list_workspaces if the user mentions a specific workspace by name.
- If a workspace name the user mentions doesn't exactly match, look for similar names. Users often misspell or use partial names (e.g. "gamin" might be "Gaming", "desig" might be "Design Team"). Suggest the closest match.

Handling Typos and Misspellings:
- Users frequently misspell drop names, categories, and workspace names. Always be forgiving.
- The search_drops tool already handles fuzzy matching, so always try it first when looking for specific drops.
- If search_drops returns nothing useful, call list_drops to show the user what's actually available — they can then pick what they meant.
- Same for workspaces: if the user names a workspace that doesn't match, list all workspaces and suggest the closest match.

Rules:
- Always pass the user_id to every tool call — never skip it.
- NEVER delete anything (drops, categories, workspaces) without explicit user confirmation. First, show the full details of what will be deleted (name, type, category, workspace, whether it has an image or content). Then ask the user "Do you want me to delete this?" Only call the delete tool after the user confirms.
- The tools already handle decryption automatically. When a tool returns content, show it to the user directly — do NOT say content is encrypted or cannot be displayed.
- Never show raw base64 or encrypted blobs to the user.
- Be natural and conversational. Talk like a helpful coworker, not a robot.
- NEVER use markdown tables.
- Use markdown formatting when responding. Do NOT use markdown tables or headers.
- When listing drops, use this format (Name label required):

I found 2 drops matching "tutorial":

1. Name: Tutorial Notes
Category: unreal engine
Preview: https://youtube.com/watch?v=abc123

2. Name: Anime List
Category: anime

Need me to open one?

- Always label the drop name with "Name:" prefix.
- Each drop is 2-3 lines max (Name, Category, Preview).
- If a drop has no category, show: Category: none
- If a drop has no content preview, skip the Preview line.
- Never include expiration dates in listings.
- Max 200 drops per user. Max file size is 500MB per individual file. There is NO total storage limit — users can use as much storage as they need.
- Text drops can optionally have an image attached. When listing or showing drops, mention if a text drop has an image attached (e.g. "has_image=1.2MB"). Users can only view/download images through the DropSync app, not through chat.
- IMPORTANT: You CANNOT access drops in the "password" category. If a user asks to view, search, or delete their saved passwords, tell them to use the DropSync app directly. You can mention how many password drops exist (from storage stats) but cannot show their content.
- When creating drops, encrypt the content automatically. You can specify workspace_id, categories (a list of up to 3 category names), and expiration ('1h', '2h', '6h', '24h', 'forever'). Default expiration is '2h'. You cannot create drops in the 'password' category. A single drop can have multiple categories — this is the preferred way, don't create separate drops for each category.
- You can update existing text drops using update_drop — change name, content, categories (comma-separated string, up to 3), or expiration. Content is automatically re-encrypted. For personal drops a new DEK is generated; for workspace drops the workspace key is used. IMPORTANT: the categories parameter REPLACES all existing categories — it does NOT append. When a user says "add a category", you must first read the drop's current categories, then pass ALL of them plus the new ones (max 3 total) to the tool.
- You can list and delete categories using list_categories and delete_category. list_categories shows how many drops use each category — use this info to tell the user which categories are empty (0 drops). Built-in categories (password, link) cannot be deleted. Never make up usage counts — always read them from the tool output.
- When the user asks to open, preview, or show a specific drop, call the preview_drop tool with the drop_id. This will open the drop in the UI. Always use this tool for preview requests — do NOT just list the drop details as text.
""",
    mcp_servers=[],  # Attached per-request in main.py
    input_guardrails=[password_guardrail],
)
