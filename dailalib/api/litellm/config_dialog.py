import logging
from typing import Optional

from dailalib.configuration import DAILAConfig
from .prompt_type import ALL_STYLES
from . import MODEL_TO_TOKENS

from libbs.ui.qt_objects import (
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QComboBox,
)

_l = logging.getLogger(__name__)
AVAILABLE_MODELS = MODEL_TO_TOKENS.keys()


class DAILAConfigDialog(QDialog):
    TITLE = "DAILA Configuration"

    def __init__(self, config: DAILAConfig, parent=None):
        """
        Constructor for the DAILA configuration dialog.
        params: 
        + config: config object, passed from litellm_api when calling this dialog
        """

        super().__init__(parent)
        self.configured = False 
        self.DAILAConfig = config

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
        self._prompt_style_edit.addItems(ALL_STYLES)
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
            _l.warning("DAILA Configuration dialog was closed without saving changes.")
        else: 
            _l.info("DAILA Configuration dialog was closed and changes were saved.")
        return self.DAILAConfig