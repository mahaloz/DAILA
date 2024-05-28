from enum import StrEnum


class PromptType(StrEnum):
    FEW_SHOT = "few-shot"
    THREE_EXPERTS = "three-experts"
    CHAIN_OF_THOUGHT = "chain-of-thought"
