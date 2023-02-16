from PySide6 import QtWidgets
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QApplication, QTextEdit, QFrame

# preparación de la matriz
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QMainWindow, QLabel, QPlainTextEdit, QPushButton


def little_endian_with_str(string):
    string_little = []
    for s in string.split(' '):
        aux = ''
        for num in reversed(s.split(':')):
            aux += num
        string_little.append(hex(int(aux, 16)))
    return string_little

def convert_little_endian_data(key, counter, nonce):
    # key = '00:01:02:03: 04:05:06:07: 08:09:0a:0b: 0c:0d:0e:0f: 10:11:12:13: 14:15:16:17: 18:19:1a:1b: 1c:1d:1e:1f'
    key_little_endian = little_endian_with_str(key)
    # counter = '01:00:00:00'
    counter_little_endian, = little_endian_with_str(counter)
    # nonce = '00:00:00:09: 00:00:00:4a: 00:00:00:00'
    nonce_little_endian = little_endian_with_str(nonce)

    return [key_little_endian, counter_little_endian, nonce_little_endian]


class ChaCha20Cipher:
    def __init__(self, constant, key, counter, nonce):
        self._constant = constant
        self._key = key
        self._counter = counter
        self._nonce = nonce
        self._state = None
        self._all_trace = ''

    def quarter_round(self, state, a, b, c, d):
        # Realiza una operación de cuarto de ronda en el estado
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] ^= state[a]
        state[d] = (state[d] << 16) & 0xffffffff | (state[d] >> 16)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] ^= state[c]
        state[b] = (state[b] << 12) & 0xffffffff | (state[b] >> 20)
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] ^= state[a]
        state[d] = (state[d] << 8) & 0xffffffff | (state[d] >> 24)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] ^= state[c]
        state[b] = (state[b] << 7) & 0xffffffff | (state[b] >> 25)
        return state

    def encrypt(self):
        # Crea una lista de estado para manipular los datos
        state = [0] * 16
        initial_state = [0] * 16
        self.final_state = [0] * 16

        initial_state[0:4] = self._constant
        initial_state[4:12] = [int(self._key[0], 16), int(self._key[1], 16), int(self._key[2], 16), int(self._key[3], 16),
                       int(self._key[4], 16), int(self._key[5], 16), int(self._key[6], 16), int(self._key[7], 16)]
        initial_state[12] = int(self._counter, 16)
        initial_state[13:16] = [int(self._nonce[0], 16), int(self._nonce[1], 16), int(self._nonce[2], 16)]
        # Inicializa el estado con las constantes y la clave
        state[0:4] = self._constant
        state[4:12] = [int(self._key[0], 16), int(self._key[1], 16), int(self._key[2], 16), int(self._key[3], 16),
                       int(self._key[4], 16), int(self._key[5], 16), int(self._key[6], 16), int(self._key[7], 16)]
        state[12] = int(self._counter, 16)
        state[13:16] = [int(self._nonce[0], 16), int(self._nonce[1], 16), int(self._nonce[2], 16)]

        # Ejecuta 20 rondas de manipulación de datos
        for i in range(10):
            state = self.quarter_round(state, 0, 4, 8, 12)
            state = self.quarter_round(state, 1, 5, 9, 13)
            state = self.quarter_round(state, 2, 6, 10, 14)
            state = self.quarter_round(state, 3, 7, 11, 15)
            state = self.quarter_round(state, 0, 5, 10, 15)
            state = self.quarter_round(state, 1, 6, 11, 12)
            state = self.quarter_round(state, 2, 7, 8, 13)
            state = self.quarter_round(state, 3, 4, 9, 14)
            # Guardar la traza
            self.give_trace(state, msg=f'State tras la iteración número {i+1}:')
        for i in range(16):
            self.final_state[i] = initial_state[i] + state[i]
        self.give_trace(self.final_state, msg='State tras salida generador:')

    # def decrypt(self):
    #     state = [0] * 16
    #     initial_state = [0] * 16
    #     final_state = [0] * 16
    #     fin = [0] * 16
    #
    #
    #     fin[0:4] = [0x0, 0x0, 0x0, 0x0]
    #     fin[4:12] = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
    #     fin[12] = 0x0
    #     fin[13:16] = [0x0, 0x0, 0xa6506ce1]
    #
    #     initial_state[0:4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    #     initial_state[4:12] = [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c]
    #     initial_state[12] = 0x1
    #     initial_state[13:16] = [0x0, 0x4a, 0x0]
    #
    #     state[0:4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    #     state[4:12] = [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c]
    #     state[12] = 0x1
    #     state[13:16] = [0x0, 0x4a, 0x0]
    #
    #
    #     # Ejecuta 20 rondas de manipulación de datos
    #     for i in range(10):
    #         state = self.quarter_round(state, 0, 4, 8, 12)
    #         state = self.quarter_round(state, 1, 5, 9, 13)
    #         state = self.quarter_round(state, 2, 6, 10, 14)
    #         state = self.quarter_round(state, 3, 7, 11, 15)
    #         state = self.quarter_round(state, 0, 5, 10, 15)
    #         state = self.quarter_round(state, 1, 6, 11, 12)
    #         state = self.quarter_round(state, 2, 7, 8, 13)
    #         state = self.quarter_round(state, 3, 4, 9, 14)
    #         # Guardar la traza
    #         self.give_trace(state, msg=f'State tras la iteración número {i + 1}:')
    #     for i in range(16):
    #         final_state[i] = initial_state[i] + state[i]
    #     self.give_trace(final_state, msg='State tras salida generador:')
    #     for i in range(16):
    #         print(f'{fin[i]} ^= {final_state[i]}')
    #         fin[i] ^= final_state[i]
    #     self.give_trace(fin, msg='Mensaje decifrado:')

    def decrypt(self):
        fin = [0] * 16
        fin[0:4] = [0x0, 0x0, 0x0, 0x0]
        fin[4:12] = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        fin[12] = 0x0
        fin[13:16] = [0x0, 0x0, 0xa6506ce1]

        for i in range(16):
            fin[i] ^= self.final_state[i]
        self.give_trace(fin, msg='State tras salida generador:')

        



    @property
    def all_trace(self):
        return self._all_trace

    def give_trace(self, state, msg):
        self._all_trace += f'\n {msg}\n'
        aux = ''
        for i in state[0:4]:
            aux += hex(i) + ', '
        self._all_trace += '\n' + aux
        aux = ''
        for i in state[4:8]:
            aux += hex(i) + ', '
        self._all_trace += '\n' + aux
        aux = ''
        for i in state[8:12]:
            aux += hex(i) + ', '
        self._all_trace += '\n' + aux
        aux = ''
        for i in state[12:16]:
            aux += hex(i) + ', '
        self._all_trace += '\n' + aux + '\n'

    def print_state(self):
        print('State Tres 20')
        aux = ''
        for i in self._state[0:4]:
            aux += hex(i) + ', '
        print(aux)
        aux = ''
        for i in self._state[4:8]:
            aux += hex(i) + ', '
        print(aux)
        aux = ''
        for i in self._state[8:12]:
            aux += hex(i) + ', '
        print(aux)
        aux = ''
        for i in self._state[12:16]:
            aux += hex(i) + ', '
        print(aux)




class MainWindow(QMainWindow):
    """Clase encargada de generar GUI y recibir los datos del usuario
    """
    def __init__(self):
        super().__init__()

        # Establecer el título de la ventana
        self.setWindowTitle("ChaCha20")
        # Establecemos el icono
        self.setWindowIcon(QIcon('candado.ico'))
        # Tamaño de la ventana
        self.setGeometry(300, 300, 800, 650)


        # Crear un widget central y establecer su layout
        central_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Crear una etiqueta de título y agregarla al layout
        title_label = QLabel("ChaCha20")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 50, QFont.Bold))
        title_label.setStyleSheet("color: red;")
        frame = QFrame()
        frame.setFrameShape(QFrame.HLine)
        layout.addWidget(title_label)
        layout.addWidget(frame)

        # Definimos un tamaño de fuente para los valores
        self.font_input = QFont("Arial", 18)
        self.font_tittles = QFont("Arial", 18, QFont.Bold)


        # Crear tres cuadros de texto para ingresar números
        key_label = QLabel("INTRODUCE LA CLAVE")
        key_label.setFont(self.font_tittles)
        self.input_key = QTextEdit()
        self.input_key.setFont(self.font_input)
        self.input_key.setFixedSize(800, 60)

        counter_label = QLabel("INTRODUCE EL CONTADOR")
        counter_label.setFont(self.font_tittles)
        self.input_counter = QTextEdit()
        self.input_counter.setFont(self.font_input)
        self.input_counter.setFixedSize(800, 30)

        nonce_label = QLabel("INTRODUCE EL NONCE")
        nonce_label.setFont(self.font_tittles)
        self.input_nonce = QTextEdit()
        self.input_nonce.setFont(self.font_input)
        self.input_nonce.setFixedSize(800, 30)

        layout.addWidget(key_label)
        layout.addWidget(self.input_key)

        layout.addWidget(counter_label)
        layout.addWidget(self.input_counter)

        layout.addWidget(nonce_label)
        layout.addWidget(self.input_nonce)



        # Crear una etiqueta para visualizar los resultados
        self.result_label = QPlainTextEdit("")
        self.result_label.setFont(self.font_input)
        # self.result_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.result_label)

        # Crear un botón para cifrar
        encrypt_button = QPushButton("Cifrar")
        layout.addWidget(encrypt_button)
        encrypt_button.clicked.connect(self.chacha20_cipher)

        # boton de decifrado
        decrypt_button = QPushButton("Decifrar")
        layout.addWidget(decrypt_button)
        decrypt_button.clicked.connect(self.chacha20_decipher)

    def chacha20_cipher(self):
        """Encargado de recopilar la infromación necesaria para ejecutar el encriptado con ayuda de ChaCha20Cipher"""
        constant = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        key, counter, nonce = convert_little_endian_data(self.input_key.toPlainText(), self.input_counter.toPlainText(),
                                                         self.input_nonce.toPlainText())
        chacha = ChaCha20Cipher(constant, key, counter, nonce)
        chacha.encrypt()
        self.result_label.setPlainText(chacha.all_trace)

    def chacha20_decipher(self):
        """Encargado de recopilar la infromación necesaria para ejecutar el encriptado con ayuda de ChaCha20Cipher"""
        constant = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
        key, counter, nonce = convert_little_endian_data(self.input_key.toPlainText(), self.input_counter.toPlainText(),
                                                         self.input_nonce.toPlainText())
        chacha = ChaCha20Cipher(constant, key, counter, nonce)
        chacha.encrypt()
        chacha.decrypt()
        self.result_label.setPlainText(chacha.all_trace)

if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
