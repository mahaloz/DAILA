
class PromptType:
    ZERO_SHOT = "zero-shot (fast, low-accuracy)"
    FEW_SHOT = "few-shot (mid-speed, mid-accuracy)"
    COT = "chain-of-thought (slow, high-accuracy)"


ALL_STYLES = [PromptType.ZERO_SHOT, PromptType.FEW_SHOT, PromptType.COT]
DEFAULT_STYLE = PromptType.FEW_SHOT
