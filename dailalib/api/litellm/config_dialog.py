import getpass
import logging
import os
import time
from pathlib import Path
from typing import Optional
from .configuration import DAILAConfig

# TODO: Avoid hardcopying from other files, but also prevent circular imports and do not make file too long 
class PromptType:
    ZERO_SHOT = "zero-shot"
    FEW_SHOT = "few-shot"
    COT = "chain-of-thought"

AVAILABLE_STYLES = [PromptType.ZERO_SHOT, PromptType.FEW_SHOT, PromptType.COT]
AVAILABLE_MODELS = {
        # TODO: update the token values for o1
        "o1-mini": 8_000,
        "o1-preview": 8_000,
        "gpt-4o": 8_000,
        "gpt-4o-mini": 16_000,
        "gpt-4-turbo": 128_000,
        "claude-3-5-sonnet-20240620": 200_000,
        "gemini/gemini-pro": 12_288,
        "vertex_ai_beta/gemini-pro": 12_288,
        # perplex is on legacy mode :( 
        "perplexity/llama-3.1-sonar-small-128k-online": 127_072,
        "perplexity/llama-3.1-sonar-medium-128k-online": 127_072,
        "perplexity/llama-3.1-sonar-large-128k-online": 127_072,
        "sonar-pro": 127_072,
        "sonar": 127_072,
    }.keys()

from libbs.ui.qt_objects import (
    QCheckBox,
    QDialog,
    QDir,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView,
    QComboBox,
)

l = logging.getLogger(__name__)

class DAILAConfigDialog(QDialog):
    TITLE = "DAILA Configuration"

    def __init__(self, DAILAConfig: DAILAConfig, parent=None):
        """
        Constructor for the DAILA configuration dialog.
        params: 
        + DAILAConfig: DAILAConfig object, passed from litellm_api when calling this dialog
        """

        super().__init__(parent)
        self.configured = False 
        self.DAILAConfig = DAILAConfig

        self.setWindowTitle(self.TITLE)
        self._main_layout = QVBoxLayout()
        self._grid_layout = QGridLayout()
        self.row = 0

        self._init_middle_widgets()
        self._main_layout.addLayout(self._grid_layout)

        self._init_close_btn_widgets()

        self.setLayout(self._main_layout)
        
    def _init_middle_widgets(self):
        """ 
        """

        # LLM Model 
        llm_model = self.DAILAConfig.model
        llm_model_label = QLabel("LLM Model:")
        llm_model_label.setToolTip("The model to use for LiteLLM.")

        # using dropdown for LLM model
        self._llm_model_edit = QComboBox(self)
        self._llm_model_edit.addItems(AVAILABLE_MODELS)
        self._llm_model_edit.setCurrentText(llm_model)
        self._grid_layout.addWidget(llm_model_label, self.row, 0)
        self._grid_layout.addWidget(self._llm_model_edit, self.row, 1)
        self.row += 1

        # API Key 

        api_key = self.DAILAConfig.api_key
        api_key_label = QLabel("API Key:")
        api_key_label.setToolTip("The API key to use for LiteLLM, for the selected model.")
        self._api_key_edit = QLineEdit(self)
        self._api_key_edit.setText(api_key)
        self._grid_layout.addWidget(api_key_label, self.row, 0)
        self._grid_layout.addWidget(self._api_key_edit, self.row, 1)
        self.row += 1

        # Prompt Style

        prompt_style = self.DAILAConfig.prompt_style
        prompt_style_label = QLabel("Prompt Style:")
        prompt_style_label.setToolTip("The prompt style for DAILA to use, refer to dailalib/litellm/prompts for details.")
        
        # using dropdown for prompt style
        self._prompt_style_edit = QComboBox(self)
        self._prompt_style_edit.addItems(AVAILABLE_STYLES)
        self._prompt_style_edit.setCurrentText(prompt_style)
        self._grid_layout.addWidget(prompt_style_label, self.row, 0)
        self._grid_layout.addWidget(self._prompt_style_edit, self.row, 1)
        self.row += 1

        # Custom OpenAI Endpoint

        custom_endpoint = self.DAILAConfig.custom_endpoint
        custom_endpoint_label = QLabel("Custom OpenAI Endpoint:")
        custom_endpoint_label.setToolTip("The custom OpenAI endpoint to use for LiteLLM.")
        self._custom_endpoint_edit = QLineEdit(self)
        self._custom_endpoint_edit.setText(custom_endpoint)
        self._grid_layout.addWidget(custom_endpoint_label, self.row, 0)
        self._grid_layout.addWidget(self._custom_endpoint_edit, self.row, 1)
        self.row += 1

        # Custom OpenAI Model

        custom_model = self.DAILAConfig.custom_model
        custom_model_label = QLabel("Custom OpenAI Model:")
        custom_model_label.setToolTip("The custom OpenAI model to use for LiteLLM.")
        self._custom_model_edit = QLineEdit(self)
        self._custom_model_edit.setText(custom_model)
        self._grid_layout.addWidget(custom_model_label, self.row, 0)
        self._grid_layout.addWidget(self._custom_model_edit, self.row, 1)
        self.row += 1

    def _init_close_btn_widgets(self):
        # buttons
        self._ok_button = QPushButton(self)
        self._ok_button.setText("OK")
        self._ok_button.setDefault(True)
        self._ok_button.clicked.connect(self._on_ok_clicked)

        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self._ok_button)
        buttons_layout.addWidget(cancel_button)

        self._main_layout.addLayout(buttons_layout)

    def _on_cancel_clicked(self):
        self.close()
    
    def parse_api_key(self, api_key_or_path: str) -> Optional[str]:
        """
        Parse the API key from the input string.
        """
        if "/" in api_key_or_path or "\\" in api_key_or_path:
            # treat as path
            with open(api_key_or_path, "r") as f:
                api_key = f.read().strip()
        else:
            api_key = api_key_or_path
        return api_key

    def _on_ok_clicked(self):
        self.DAILAConfig.model = self._llm_model_edit.currentText()
        self.DAILAConfig.api_key = self.parse_api_key(self._api_key_edit.text())
        self.DAILAConfig.prompt_style = self._prompt_style_edit.currentText()
        self.DAILAConfig.custom_endpoint = self._custom_endpoint_edit.text()
        self.DAILAConfig.custom_model = self._custom_model_edit.text()
        self.configured = True
        self.close()
        
    def config_dialog_exec(self):
        self.exec()
        if not self.configured: 
            l.warning("DAILA Configuration dialog was closed without saving changes.")
        else: 
            l.info("DAILA Configuration dialog was closed and changes were saved.")
        return self.DAILAConfig