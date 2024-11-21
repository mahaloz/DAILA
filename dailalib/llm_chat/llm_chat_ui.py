import typing

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QPushButton, QLabel, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QCoreApplication
from PyQt5.QtGui import QFont

from libbs.artifacts.context import Context

if typing.TYPE_CHECKING:
    from ..api.litellm.litellm_api import LiteLLMAIAPI

CONTEXT_PROMPT = """
You are reverse engineering assistant that helps to understand binaries in a decompiler. Given decompilation 
and questions you answer them to the best of your ability. Here is the function you are currently working on:
```
DEC_TEXT
```

Acknowledging the context, by responding with:
"I see you are working on function <function_name>. How can I help you today?"
"""


class LLMChatClient(QWidget):
    def __init__(self, ai_api: "LiteLLMAIAPI", parent=None, context: Context = None):
        super(LLMChatClient, self).__init__(parent)
        self.model = ai_api.get_model()
        self.ai_api = ai_api
        self.context = context
        self.setWindowTitle('LLM Chat')
        self.setGeometry(100, 100, 600, 800)

        # Main layout
        self.layout = QVBoxLayout(self)
        self.setLayout(self.layout)

        # Scroll area for chat messages
        self.chat_area = QScrollArea()
        self.chat_area.setWidgetResizable(True)
        self.chat_content = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.addStretch(1)
        self.chat_area.setWidget(self.chat_content)

        # Input area
        self.input_text = QTextEdit()
        self.input_text.setFixedHeight(80)

        # Send button
        self.send_button = QPushButton('Send')
        self.send_button.setFixedHeight(40)
        self.send_button.clicked.connect(lambda: self.send_message())

        # Arrange input and send button horizontally
        self.input_layout = QHBoxLayout()
        self.input_layout.addWidget(self.input_text)
        self.input_layout.addWidget(self.send_button)

        # Add widgets to the main layout
        self.layout.addWidget(self.chat_area)
        self.layout.addLayout(self.input_layout)

        # Chat history
        self.chat_history = []

        # model check
        if not self.model:
            self.ai_api.warning("No model set. Close the chat window and please set a model before using the chat")
            return

        # preset the very first interaction
        # create a context for this first message
        if ai_api.chat_use_ctx:
            ai_api.info("Collecting context for the current function...")
            if context is None:
                context = ai_api._dec_interface.gui_active_context()
            dec = ai_api._dec_interface.decompile(context.func_addr)
            dec_text = dec.text if dec is not None else None
            if dec_text:
                # put a number in front of each line
                dec_lines = dec_text.split("\n")
                dec_text = "\n".join([f"{i + 1} {line}" for i, line in enumerate(dec_lines)])
                prompt = CONTEXT_PROMPT.replace("DEC_TEXT", dec_text)
                # set the text to the prompt
                self.input_text.setText(prompt)
                self.send_message(add_text=False, role="system")
        else:
            self.input_text.setText("You are an assistant that helps understand code. Start the conversation by simply saying 'Hello, how can I help you?'.")
            self.send_message(add_text=False, role="system")

    def add_message(self, text, is_user):
        # Message bubble
        message_label = QLabel(text)
        message_label.setWordWrap(True)
        message_label.setFont(QFont('Arial', 12))
        message_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # Bubble styling
        bubble = QFrame()
        bubble_layout = QHBoxLayout()
        bubble.setLayout(bubble_layout)

        if is_user:
            # User message on the right
            message_label.setStyleSheet("""
                background-color: #DCF8C6;
                color: black;
                padding: 10px;
                border-radius: 10px;
            """)
            bubble_layout.addStretch()
            bubble_layout.addWidget(message_label)
        else:
            # Assistant message on the left
            message_label.setStyleSheet("""
                background-color: #FFFFFF;
                color: black;
                padding: 10px;
                border-radius: 10px;
            """)
            bubble_layout.addWidget(message_label)
            bubble_layout.addStretch()

        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        QCoreApplication.processEvents()
        self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())

    def send_message(self, add_text=True, role="user"):
        user_text = self.input_text.toPlainText().strip()
        if not user_text:
            return

        # do aiapi calback
        if self.ai_api:
            send_callback = self.ai_api.chat_event_callbacks.get("send", None)
            if send_callback:
                send_callback(user_text)

        # Display user message
        if add_text:
            self.add_message(user_text, is_user=True)
        self.input_text.clear()

        # Append to chat history
        self.chat_history.append({"role": role, "content": user_text})

        # Disable input while waiting for response
        self.input_text.setDisabled(True)
        self.send_button.setDisabled(True)

        # Start a thread to get the response
        self.thread = LLMThread(self.chat_history, self.model)
        self.thread.response_received.connect(lambda msg: self.receive_message(msg))
        self.thread.start()

    def receive_message(self, assistant_message):
        # Display assistant message
        self.add_message(assistant_message, is_user=False)

        # do aiapi calback
        if self.ai_api:
            recv_callback = self.ai_api.chat_event_callbacks.get("receive", None)
            if recv_callback:
                recv_callback(assistant_message)

        # Append to chat history
        self.chat_history.append({"role": "user", "content": assistant_message})

        # Re-enable input
        self.input_text.setDisabled(False)
        self.send_button.setDisabled(False)

    def closeEvent(self, event):
        # Ensure that the thread is properly terminated when the window is closed
        if hasattr(self, 'thread') and self.thread.isRunning():
            self.thread.terminate()
        event.accept()


class LLMThread(QThread):
    response_received = pyqtSignal(str)

    def __init__(self, chat_history, model_name):
        super().__init__()
        self.chat_history = chat_history.copy()
        self.model_name = model_name

    def run(self):
        from litellm import completion

        response = completion(
            model=self.model_name,
            messages=self.chat_history,
            timeout=60,
        )

        try:
            answer = response.choices[0].message.content
        except (KeyError, IndexError) as e:
            answer = f"Error: {e}. Please close the window and try again."

        self.response_received.emit(answer)
