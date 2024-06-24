
class PromptType:
    ZERO_SHOT = "zero-shot"
    FEW_SHOT = "few-shot"


ALL_STYLES = [PromptType.ZERO_SHOT, PromptType.FEW_SHOT]
DEFAULT_STYLE = PromptType.FEW_SHOT
