// Emulator klawiatury CJMUC-32 z układem ATMEGA32U4

#include <Keyboard.h>
#include <SPI.h>
#include <SD.h>

#define KEY_MENU 0xED
#define KEY_BREAK 0xD0
#define KEY_NUMLOCK 0xDB
#define KEY_PRINTSCREEN 0xCE
#define KEY_SCROLLLOCK 0xCF
#define KEY_SPACE 0xB4
#define KEY_LEFT_CTRL 0x80
#define KEY_LEFT_SHIFT 0x81
#define KEY_LEFT_ALT 0x82
#define KEY_LEFT_GUI 0x83
#define KEY_RIGHT_CTRL 0x84
#define KEY_RIGHT_SHIFT 0x85
#define KEY_RIGHT_ALT 0x86
#define KEY_RIGHT_GUI 0x87
#define KEY_UP_ARROW 0xDA
#define KEY_DOWN_ARROW 0xD9
#define KEY_LEFT_ARROW 0xD8
#define KEY_RIGHT_ARROW 0xD7
#define KEY_BACKSPACE 0xB2
#define KEY_TAB 0xB3
#define KEY_RETURN 0xB0
#define KEY_ESC 0xB1
#define KEY_INSERT 0xD1
#define KEY_DELETE 0xD4
#define KEY_PAGE_UP 0xD3
#define KEY_PAGE_DOWN 0xD6
#define KEY_HOME 0xD2
#define KEY_END 0xD5
#define KEY_CAPS_LOCK 0xC1
#define KEY_F1 0xC2
#define KEY_F2 0xC3
#define KEY_F3 0xC4
#define KEY_F4 0xC5
#define KEY_F5 0xC6
#define KEY_F6 0xC7
#define KEY_F7 0xC8
#define KEY_F8 0xC9
#define KEY_F9 0xCA
#define KEY_F10 0xCB
#define KEY_F11 0xCC
#define KEY_F12 0xCD

const int chipSelect = 4;
String cmd;
String arg;
String mode;
String payload;
String prevCmd;
String prevArg;
char argChar;
char prevArgChar;
char charBuff;
char breakChar;
int defaultDelay = 0;
int led2 = 8;
File root;
File myFile;
bool errLog = false;
byte inChar[64];
byte modifier[64];
byte outChar[64];
byte modifierKey;

void setup() {
  pinMode(led2, OUTPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  Keyboard.begin();
  Serial.begin(9600);

  if (!SD.begin(chipSelect)) {
    Serial.println("Card failed, or not present");
    return;
  }

  root = SD.open("/");

  mode = readConfig("mode.cfg");
  payload = readConfig("exec.cfg");

  if (payload == "") {
    Serial.println("No payload configured (exec.cfg missing or empty)");
    return;
  }

  if (mode == "c") {
    delivery(payload);
  }
  else if (mode == "a") {
    delivery(payload);
    mode = "m";
    writeConfig("mode.cfg", mode);
  }
  else if (mode == "m") {
    management();
  }

  Keyboard.end();
}

void management() {
  digitalWrite(led2, HIGH);

  while (!Serial) {
    if (errLog) {
      digitalWrite(led2, HIGH);
      delay(200);
      digitalWrite(led2, LOW);
      delay(200);
    }
  }

  Serial.println("Available payloads:");
  printDirectory(root, 0);
  root.close();
  Serial.println();
  Serial.println("Available modes: ");
  Serial.println("m => management mode");
  Serial.println("a => auto-disarm mode");
  Serial.println("c => continuous delivery mode");
  Serial.println();
  Serial.print("Current mode: ");
  Serial.println(mode);
  Serial.print("Current payload: ");
  Serial.println(payload);
  Serial.println();
  Serial.println("Input mode:");
  writeConfig("mode.cfg", inputData());
  Serial.println();
  Serial.println("Input payload:");
  writeConfig("exec.cfg", inputData());
  Serial.println();
}

void printDirectory(File dir, int numTabs) {
  while (true) {
    File entry =  dir.openNextFile();
    if (! entry) {
      break;
    }
    for (uint8_t i = 0; i < numTabs; i++) {
      Serial.print('\t');
    }
    Serial.print(entry.name());
    if (entry.isDirectory()) {
      Serial.println("/");
      printDirectory(entry, numTabs + 1);
    } else {
      Serial.print("\t\t");
      Serial.println(entry.size(), DEC);
    }
    entry.close();
  }
}

String inputData() {
  String inputStr;
  while (1) {
    if (Serial.available() > 0) {
      inputStr = Serial.readStringUntil('\n');
      break;
    }
  }
  return inputStr;
}

byte convertLangChar(byte in) {
  for (int i = 0; i < 64; i++) { // not <= 64
    if (inChar[i] && inChar[i] == in) {
      modifierKey = modifier[i];
      return outChar[i];
    }
  }
  modifierKey = 0;
  return in; // fallback
}

void printChar(byte in) {
  if (modifierKey) {
    Keyboard.press(modifierKey);
    delay(5);
    Keyboard.write(in);
    delay(5);
    Keyboard.release(modifierKey);
    modifierKey = 0;
  }
  else {
    Keyboard.write(in);
    delay(5);
  }
}

void pressChar(byte in) {
  if (modifierKey) {
    Keyboard.press(modifierKey);
    delay(5);
    Keyboard.press(in);
    delay(5);
    Keyboard.release(modifierKey);
    modifierKey = 0;
  }
  else {
    Keyboard.press(in);
    delay(5);
  }
}

String readConfig(String fileName) {
  String fileContent = "";
  myFile = SD.open(fileName);
  if (myFile) {
    while (myFile.available()) {
      fileContent += char(myFile.read());
    }
    myFile.close();
    fileContent.trim();
    return fileContent;
  } else {
    Serial.println("error opening file");
    return "";
  }
}

void writeConfig(String fileName, String inputData) {
  SD.remove(fileName);
  myFile = SD.open(fileName, FILE_WRITE);
  if (myFile) {
    myFile.print(inputData);
    myFile.close();
  }
}

void delivery (String fileName) {
  delay(800);
  File dataFile = SD.open(fileName);

  if (dataFile) {
    while (dataFile.available()) {
      if (defaultDelay != 0) {
        delay(defaultDelay);
      }

      parseCmd(dataFile);

      if (cmd == "") {
        continue;
      }
      else if (cmd == "GUI" || cmd == "WINDOWS") {
        if (breakChar == ' ') {
          argChar = dataFile.read();
          cmdGui(argChar);
          dataFile.read(); // remove trailing \n
        }
        else {
          cmdGui(0x00);
        }
      }
      else if (cmd == "CTRL") {
        if (breakChar == ' ') {
          argChar = dataFile.read();
          Keyboard.press(KEY_LEFT_CTRL);
          pressChar(convertLangChar(argChar));
          delay(100);
          Keyboard.releaseAll();
          dataFile.read(); // remove trailing \n
        }
      }
      else if (cmd == "ALT") {
        if (breakChar == ' ') {
          argChar = dataFile.read();
          Keyboard.press(KEY_LEFT_ALT);
          pressChar(convertLangChar(argChar));
          delay(100);
          Keyboard.releaseAll();
          dataFile.read(); // remove trailing \n
        }
      }
      else if (cmd == "CTRLALT") {
        if (breakChar == ' ') {
          argChar = dataFile.read();
          Keyboard.press(KEY_LEFT_CTRL);
          Keyboard.press(KEY_LEFT_ALT);
          pressChar(convertLangChar(argChar));
          delay(100);
          Keyboard.releaseAll();
          dataFile.read(); // remove trailing \n
        }
      }
      else if (cmd == "DELAY") {
        parseArg(dataFile);
        cmdDelay(arg);
      }
      else if (cmd == "STRING") {
        cmdString(dataFile);
      }
      else if (cmd == "ENTER") {
        cmdPressKey(KEY_RETURN);
      }
      else if (cmd == "REM") {
        if (breakChar == ' ') {
          parseArg(dataFile);
        }
        cmdRem();
      }
      else if (cmd == "DEFAULT_DELAY" || cmd == "DEFAULTDELAY") {
        parseArg(dataFile);
        defaultDelay = arg.toInt();
        cmd = "";
        arg = "";
      }
      else if (cmd == "MENU" || cmd == "APP") {
        cmdPressKey(KEY_MENU);
      }
      else if (cmd == "DOWNARROW" || cmd == "DOWN") {
        cmdPressKey(KEY_DOWN_ARROW);
      }
      else if (cmd == "LEFTARROW" || cmd == "LEFT") {
        cmdPressKey(KEY_LEFT_ARROW);
      }
      else if (cmd == "RIGHTARROW" || cmd == "RIGHT") {
        cmdPressKey(KEY_RIGHT_ARROW);
      }
      else if (cmd == "UPARROW" || cmd == "UP") {
        cmdPressKey(KEY_UP_ARROW);
      }
      else if (cmd == "BREAK" || cmd == "PAUSE") {
        cmdPressKey(KEY_BREAK);
      }
      else if (cmd == "CAPSLOCK") {
        cmdPressKey(KEY_CAPS_LOCK);
      }
      else if (cmd == "DELETE") {
        cmdPressKey(KEY_DELETE);
      }
      else if (cmd == "END") {
        cmdPressKey(KEY_END);
      }
      else if (cmd == "ESC" || cmd == "ESCAPE") {
        cmdPressKey(KEY_ESC);
      }
      else if (cmd == "HOME") {
        cmdPressKey(KEY_HOME);
      }
      else if (cmd == "INSERT") {
        cmdPressKey(KEY_INSERT);
      }
      else if (cmd == "NUMLOCK") {
        cmdPressKey(KEY_NUMLOCK);
      }
      else if (cmd == "PAGEUP") {
        cmdPressKey(KEY_PAGE_UP);
      }
      else if (cmd == "PAGEDOWN") {
        cmdPressKey(KEY_PAGE_DOWN);
      }
      else if (cmd == "PRINTSCREEN") {
        cmdPressKey(KEY_PRINTSCREEN);
      }
      else if (cmd == "SCROLLLOCK") {
        cmdPressKey(KEY_SCROLLLOCK);
      }
      else if (cmd == "SPACE") {
        cmdPressKey(KEY_SPACE);
      }
      else if (cmd == "TAB") {
        cmdPressKey(KEY_TAB);
      }
      else if (cmd == "F1") {
        cmdPressKey(KEY_F1);
      }
      else if (cmd == "F2") {
        cmdPressKey(KEY_F2);
      }
      else if (cmd == "F3") {
        cmdPressKey(KEY_F3);
      }
      else if (cmd == "F4") {
        cmdPressKey(KEY_F4);
      }
      else if (cmd == "F5") {
        cmdPressKey(KEY_F5);
      }
      else if (cmd == "F6") {
        cmdPressKey(KEY_F6);
      }
      else if (cmd == "F7") {
        cmdPressKey(KEY_F7);
      }
      else if (cmd == "F8") {
        cmdPressKey(KEY_F8);
      }
      else if (cmd == "F9") {
        cmdPressKey(KEY_F9);
      }
      else if (cmd == "F10") {
        cmdPressKey(KEY_F10);
      }
      else if (cmd == "F11") {
        cmdPressKey(KEY_F11);
      }
      else if (cmd == "F12") {
        cmdPressKey(KEY_F12);
      }
      else {
        errLog = true;
        cmd = "";
        arg = "";
        continue;
      }
    }
    dataFile.close();
    Keyboard.releaseAll();
    digitalWrite(led2, HIGH);
    delay(500);
    digitalWrite(led2, LOW);
  }
  else {
    Serial.println("Error opening script file");
  }
}

void cmdRem () {
  cmd = "";
  arg = "";
}

void cmdDelay (String arg_l) {
  delay(arg_l.toInt());
  prevCmd = cmd;
  cmd = "";
  prevArg = arg_l;
  arg = "";
}

void cmdGui (char argChar_l) {
  Keyboard.press(KEY_LEFT_GUI);
  delay(100);
  if (argChar_l != 0x00) {
    pressChar(convertLangChar(argChar_l));
    delay(100);
  }
  Keyboard.releaseAll();
  prevCmd = cmd;
  cmd = "";
  prevArgChar = argChar_l;
  argChar = 0x00;
}

void cmdPressKey(int key) {
  pressChar(convertLangChar(key));
  delay(100);
  Keyboard.releaseAll();
  prevCmd = cmd;
  cmd = "";
  prevArg = arg;
  arg = "";
}

void cmdString (File dataFile) {
  while (true) {
    charBuff = dataFile.read();
    if (charBuff == '\n') {
      //Keyboard.print(charBuff); //adds \n at the end of the line
      break;
    }
    else {
      //Keyboard.print(charBuff);
      printChar(convertLangChar(charBuff));
    }
  }
  cmd = "";
  arg = "";
}

void parseCmd(File dataFile) {
  cmd = ""; // reset before reuse
  while (true) {
    charBuff = dataFile.read();
    if (charBuff == ' ' || charBuff == '\n' || cmd.length() > 15) {
      breakChar = charBuff;
      break;
    }
    else {
      cmd = cmd + charBuff;
    }
  }
  cmd.trim();
}

void parseArg(File dataFile) {
  arg = ""; // reset before reuse
  while (true) {
    charBuff = dataFile.read();
    if (charBuff == '\n') {
      break;
    }
    else {
      arg = arg + charBuff;
    }
  }
}

void loop() {
}
