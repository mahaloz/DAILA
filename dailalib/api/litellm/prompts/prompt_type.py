
class PromptType:
    ZERO_SHOT = "zero-shot"
    FEW_SHOT = "few-shot"
    COT = "chain-of-thought"


ALL_STYLES = [PromptType.ZERO_SHOT, PromptType.FEW_SHOT, PromptType.COT]
DEFAULT_STYLE = PromptType.FEW_SHOT
