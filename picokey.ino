#include <Arduino.h>
#include <Hash.h>
#include <FatFS.h>
#include <FatFSUSB.h>
#include <EEPROM.h>
#include "AESLib.h"
#include <Crypto.h>
#include <SHA256.h>

#define EEPROM_SIZE 4096        // 模拟 EEPROM 大小
#define HASH_SIZE 20            // SHA1 哈希大小
#define HASH_ADDRESS 0          // 哈希存储的起始地址
#define PASSWORD_MAX_LENGTH 32  // 密码最大长度
volatile bool fsForPC = false;  // 默认块由 MCU 使用
volatile bool updated = false;
volatile bool driveConnected = false;
volatile bool inPrinting = false;
String rawPasswd;


const int EEPROM_OFFSET = 1024; // 偏移地址

#define TIME_STEP 30          // 时间步长（秒）

// TOTP 数据结构
struct TOTPToken {
  char tag[16];
  char base32Secret[32];
} __attribute__((packed)); // 禁用对齐优化
// 定义 Arduino 的 ASCII 标志
const char* arduino_logo[] = {
  "   /\\__\\     /\\  \\     /\\__\\    /\\__\\  ",
  "  /::L_L_   _\\:\\  \\   /:/  /   /:/ _/_ ",
  " /:/L:\\__\\ /\\/::\\__\\ /:/__/   /::-\"\\__\\",
  " \\/_:/  / \\::/\\/__/ \\:\\  \\   \\;:;-\",-\" ",
  "   /:/  /   \\:\\__\\    \\:\\__\\   |:|  |  ",
  "   \\/__/     \\/__/     \\/__/    \\|__|",
  "    ___       ___       ___",
  "   /\\  \\     /\\  \\     /\\  \\",
  "  /::\\  \\   /::\\  \\    \\:\\  \\",
  " /:/\\:\\__\\ /::\\:\\__\\   /::\\__\\",
  " \\:\\ \\/__/ \\/\\::/  /  /:/\\/__/",
  "  \\:\\__\\     /:/  /  /:/  /",
  "   \\/__/     \\/__/   \\/__/"
};

const char* info_lines[] = {
  "Board        : RP2350",
  "CPU Arch     : ARM Cortex-M33",
  "CPU Frequency: 150 MHz",
  "SRAM         : 264 KB",
  "Flash        : 4 MB"
};

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    delay(10);
  }
  delay(3000);

  // 初始化 FatFS 文件系统
  if (!FatFS.begin()) {
    Serial.println("FatFS initialization failed!");
    while (1) {
      delay(1);
    }
  }
  Serial.println("FatFS initialization done.");
  randomSeed(analogRead(A0));
  inPrinting = true;
  //printDirectory("/", 0);
  inPrinting = false;

  // 初始化 USB 文件共享回调（不启动共享）
  FatFSUSB.onUnplug(unplug);
  FatFSUSB.onPlug(plug);
  FatFSUSB.driveReady(mountable);

  // 注意：FatFSUSB.begin() 未被调用，默认 USB 文件共享关闭
  Serial.println("USB drive mode is disabled by default.");

  // 初始化模拟 EEPROM
  EEPROM.begin(EEPROM_SIZE);
  Serial.println("EEPROM initialized.");

  // 检查是否已有密码哈希
  uint8_t storedHash[HASH_SIZE];
  bool hasPassword = false;

  // 读取哈希值并检查是否设置
  for (int i = 0; i < HASH_SIZE; i++) {
    storedHash[i] = EEPROM.read(HASH_ADDRESS + i);
    if (storedHash[i] != 0xFF) {  // EEPROM 默认未写入值为 0xFF
      hasPassword = true;
    }
  }

  if (hasPassword) {
    Serial.println("Password is already set.");
    while (!verifyPassword(storedHash))  // 验证密码
    {
      delay(1000);
    }
    // 欢迎消息
    printNeofetch() ;
    Serial.println("Welcome to RP2350 Terminal!");
    Serial.println("Type 'help' to see available commands.");
    Serial.print("> ");  // 命令提示符
  } else {
    Serial.println("No password found. Please set a new password.");
    setPassword();  // 设置新密码
  }
}


void loop() {

  // 检查用户输入
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    command.trim();          // 去掉多余空格和换行符
    handleCommand(command);  // 处理用户输入的命令
    Serial.print("> ");      // 提示符
  }
  delay(10);
}

// Called by FatFSUSB when the drive is released.  We note this, restart FatFS, and tell the main loop to rescan.
void unplug(uint32_t i) {
  (void)i;
  driveConnected = false;
  updated = true;
  FatFS.begin();
}

// Called by FatFSUSB when the drive is mounted by the PC.  Have to stop FatFS, since the drive data can change, note it, and continue.
void plug(uint32_t i) {
  (void)i;
  driveConnected = true;
  FatFS.end();
}

// Called by FatFSUSB to determine if it is safe to let the PC mount the USB drive.  If we're accessing the FS in any way, have any Files open, etc. then it's not safe to let the PC mount the drive.
bool mountable(uint32_t i) {
  (void)i;
  return !inPrinting;
}



void handleCommand(String command) {
  command.trim();         // 移除空格和换行符
  command.toLowerCase();  // 将命令转换为小写

  if (command.length() == 0) {
    return;  // 忽略空命令
  }

  Serial.println(command);

  // 定义命令的哈希值或标识符
  int commandType = 0;
  if (command == "help") {
    commandType = 1;
  } else if (command.startsWith("switch_fs")) {
    commandType = 2;
  } else if (command == "fs_status") {
    commandType = 3;
  } else if (command == "encrypt_db") {
    commandType = 4;
  } else if (command.startsWith("ls")) {
    commandType = 5;
  } else if (command.startsWith("rm ")) {
    commandType = 6;
  } else if (command.startsWith("find")) {
    commandType = 7;
  } else if (command == "exit") {
    commandType = 8;
  } else if (command.startsWith("add")) {
    commandType = 9;
  } else if (command == "reset") {
    commandType = 10;
  }  else if (command == "change_password") {
    commandType = 11;
  } else {
    commandType = -1;  // 未知命令
  }

  // 根据命令类型执行相应操作
  switch (commandType) {
    case 1:  // help
      showHelp();
      break;

    case 2:
      {  // switch_fs
        String mode = command.substring(command.indexOf(" ") + 1);
        mode.trim();
        switchFS(mode);
        break;
      }

    case 3:  // fs_status
      queryFSStatus();
      break;

    case 4:  // encrypt_db
      encryptDatabase();
      break;

    case 5:
      {  // ls
        String dirName = command.substring(command.indexOf(" ") + 1);
        dirName.trim();
           // 如果用户没有提供目录名，则默认为根目录 "/"
        if (dirName.length() == 0) {
          dirName = "";
        } else {
          dirName = "/" + dirName; // 拼接路径
        }

        listFiles(dirName.c_str()); // 将 String 转换为 const char*
        break;
      }

    case 6:
      {  // rm
        String filename = command.substring(3);
        filename.trim();
        removeFile(filename.c_str());
        break;
      }

    case 7:
      {  // query_site
        String site = command.substring(command.indexOf(" ") + 1);
        site.trim();
        querySite(site.c_str());
        break;
      }

    case 8:  // exit
      safeExit();
      break;

    case 9:
      {  // append_db
        String input = command.substring(command.indexOf(" ") + 1);
        input.trim();

        // 确保用户输入了完整的信息
        if (input.length() == 0) {
          Serial.println("Usage: append_db <url>,<username>,<password>");
          break;
        }

        // 分割输入为 URL、用户名和密码
        int firstComma = input.indexOf(',');
        int secondComma = input.indexOf(',', firstComma + 1);

        if (firstComma == -1 || secondComma == -1) {
          Serial.println("Invalid format. Usage: append_db <url>,<username>,<password>");
          break;
        }

        String url = input.substring(0, firstComma);
        url.trim();  // 调用 .trim() 修改 url

        String username = input.substring(firstComma + 1, secondComma);
        username.trim();  // 调用 .trim() 修改 username

        String password = input.substring(secondComma + 1);
        password.trim();  // 调用 .trim() 修改 password

        // 调用追加函数
        appendToEncryptedDatabase(url.c_str(), username.c_str(), password.c_str());
        break;
      }
    case 10:  // exit
      resetSystem();
      break;

    case 11:  // exit
      changePassword();
      break;

    default:  // 未知命令
      Serial.println("Unknown command. Type 'help' for a list of available commands.");
      break;
  }
}


void showHelp() {
Serial.println("Available commands:");
Serial.println("  help          - Show this help message");
Serial.println("  switch_fs mcu - Switch file system block to MCU");
Serial.println("  switch_fs pc  - Switch file system block to PC");
Serial.println("  fs_status     - Query current file system block status");
Serial.println("  ls            - List all files and directories");
Serial.println("  rm <filename> - Remove a specified file");
Serial.println("  add           - Add a new entry to the database (<url>,<username>,<password>)");
Serial.println("  find          - Query the password database for a specific website");
Serial.println("  encrypt_db    - Encrypt the password database file (requires key input)");
Serial.println("  change_password - Change the master password");
Serial.println("  reset         - Reset system and clear data");
Serial.println("  exit          - Exit the program and save data");

}


void printNeofetch() {
  Serial.println();

  // 打印 ASCII 艺术和信息
  int logo_lines = sizeof(arduino_logo) / sizeof(arduino_logo[0]);
  int info_lines_count = sizeof(info_lines) / sizeof(info_lines[0]);

  for (int i = 0; i < max(logo_lines, info_lines_count); i++) {
    if (i < logo_lines) {
      Serial.print(arduino_logo[i]);  // 打印 ASCII 艺术
    } else {
      Serial.print("                    ");  // 占位符，让文字右对齐
    }

    if (i < info_lines_count) {
      Serial.print("    ");           // 空格间隔
      Serial.println(info_lines[i]);  // 打印右边的信息
    } else {
      Serial.println();  // 仅打印空行
    }
  }
  Serial.println("=====================================");
}

void printDirectory(String dirName, int numTabs) {
  Dir dir = FatFS.openDir(dirName);

  while (true) {

    if (!dir.next()) {
      // no more files
      break;
    }
    for (uint8_t i = 0; i < numTabs; i++) {
      Serial.print('\t');
    }
    Serial.print(dir.fileName());
    if (dir.isDirectory()) {
      Serial.println("/");
      printDirectory(dirName + "/" + dir.fileName(), numTabs + 1);
    } else {
      // files have sizes, directories do not
      Serial.print("\t\t");
      Serial.print(dir.fileSize(), DEC);
      time_t cr = dir.fileCreationTime();
      struct tm* tmstruct = localtime(&cr);
      Serial.printf("\t%d-%02d-%02d %02d:%02d:%02d\n", (tmstruct->tm_year) + 1900, (tmstruct->tm_mon) + 1, tmstruct->tm_mday, tmstruct->tm_hour, tmstruct->tm_min, tmstruct->tm_sec);
    }
  }
}


// 函数：验证密码
int verifyPassword(uint8_t storedHash[]) {
  Serial.println("Enter your password to verify:");

  while (!Serial.available()) {
    delay(100);  // 等待用户输入
  }
  String inputPassword = Serial.readStringUntil('\n');  // 获取用户输入
  inputPassword.trim();                                 // 移除多余空格和换行符

  // 计算输入密码的哈希值
  uint8_t inputHash[HASH_SIZE];
  sha1(inputPassword.c_str(), inputHash);

  // 验证哈希值
  bool match = true;
  for (int i = 0; i < HASH_SIZE; i++) {
    if (storedHash[i] != inputHash[i]) {
      match = false;
      break;
    }
  }

  if (match) {
    Serial.println("Password verified successfully!");
    rawPasswd = inputPassword;
    return 1;
    printNeofetch();
  } else {
    Serial.println("Incorrect password!");
    return 0;
  }
}


// 函数：设置新密码
void setPassword() {
  String newPassword, confirmPassword;

  // 提示用户输入新密码
  Serial.println("Enter a new password:");
  while (!Serial.available()) {
    delay(100);  // 等待用户输入
  }
  newPassword = Serial.readStringUntil('\n');  // 获取用户输入的密码
  newPassword.trim();                          // 移除多余空格和换行符

  if (newPassword.length() > PASSWORD_MAX_LENGTH) {
    Serial.println("Password too long! Maximum length is 32 characters.");
    return;
  }

  // 提示用户再次输入新密码
  Serial.println("Confirm your new password:");
  while (!Serial.available()) {
    delay(100);  // 等待用户输入
  }
  confirmPassword = Serial.readStringUntil('\n');  // 获取用户确认的密码
  confirmPassword.trim();                          // 移除多余空格和换行符

  // 验证两次输入的密码是否一致
  if (newPassword != confirmPassword) {
    Serial.println("Passwords do not match! Try again.");
    return;
  }

  // 计算新密码的哈希值
  uint8_t newHash[HASH_SIZE];
  sha1(newPassword.c_str(), newHash);

  // 将哈希值存入 EEPROM
  Serial.println("Saving password...");
  for (int i = 0; i < HASH_SIZE; i++) {
    EEPROM.write(HASH_ADDRESS + i, newHash[i]);
  }
  EEPROM.commit();
  Serial.println("Password saved successfully!");
  rawPasswd = newPassword;
  delay(1000); 
  rp2040.reboot();
}
// 修改密码
void changePassword() {
  Serial.println("Enter your current password:");
  String currentPassword;
  while (!Serial.available()) {
    delay(100);  // 等待用户输入
  }
  currentPassword = Serial.readStringUntil('\n');
  currentPassword.trim();  // 移除多余空格和换行符

  // 验证当前密码
  uint8_t storedHash[HASH_SIZE];
  for (int i = 0; i < HASH_SIZE; i++) {
    storedHash[i] = EEPROM.read(HASH_ADDRESS + i);
  }
  uint8_t inputHash[HASH_SIZE];
  sha1(currentPassword.c_str(), inputHash);

  bool match = true;
  for (int i = 0; i < HASH_SIZE; i++) {
    if (storedHash[i] != inputHash[i]) {
      match = false;
      break;
    }
  }

  if (!match) {
    Serial.println("Incorrect password!");
    return;
  }
  
  // 解密数据库
  const char* encryptedFile = "passwords.enc";
  const char* tempFile = "passwords.tmp";
  uint8_t oldAesKey[16];
  generateAesKey(currentPassword.c_str(), oldAesKey, sizeof(oldAesKey));
  if (!decryptFile(encryptedFile, tempFile, oldAesKey, sizeof(oldAesKey))) {
    Serial.println("Failed to decrypt the database. Check your current password.");
    return;
  }

  // 输入新密码
  Serial.println("Enter your new password:");
  String newPassword;
  while (!Serial.available()) {
    delay(100);  // 等待用户输入
  }
  newPassword = Serial.readStringUntil('\n');
  newPassword.trim();

  if (newPassword.length() > PASSWORD_MAX_LENGTH) {
    Serial.println("Password too long! Maximum length is 32 characters.");
    return;
  }

  // 再次确认新密码
  Serial.println("Confirm your new password:");
  String confirmPassword;
  while (!Serial.available()) {
    delay(100);  // 等待用户输入
  }
  confirmPassword = Serial.readStringUntil('\n');
  confirmPassword.trim();

  if (newPassword != confirmPassword) {
    Serial.println("Passwords do not match! Try again.");
    return;
  }
  // 使用新密码加密数据库
  uint8_t newAesKey[16];
  generateAesKey(newPassword.c_str(), newAesKey, sizeof(newAesKey));
  if (!encryptFile(tempFile, encryptedFile, newAesKey, sizeof(newAesKey))) {
    Serial.println("Failed to re-encrypt the database with the new password.");
    return;
  }

  // 删除临时文件
  FatFS.remove(tempFile);
  // 计算新密码的哈希值并存储到 EEPROM
  uint8_t newHash[HASH_SIZE];
  sha1(newPassword.c_str(), newHash);

  for (int i = 0; i < HASH_SIZE; i++) {
    EEPROM.write(HASH_ADDRESS + i, newHash[i]);
  }
  EEPROM.commit();
  Serial.println("Password changed successfully!");
  rawPasswd = newPassword;
}

// 切换文件系统块
void switchFS(String mode) {
  if (mode == "mcu") {
    if (fsForPC) {
      // 当前块为 PC 使用，切换回 MCU 使用
      FatFSUSB.end();  // 停止 PC 访问
      FatFS.begin();   // 开启 MCU 访问
      fsForPC = false;
      Serial.println("File system block switched to MCU.");
    } else {
      Serial.println("File system block is already for MCU.");
    }
  } else if (mode == "pc") {
    if (!fsForPC) {
      // 当前块为 MCU 使用，切换为 PC 使用
      FatFS.end();       // 停止 MCU 访问
      FatFSUSB.begin();  // 开启 PC 访问
      fsForPC = true;
      Serial.println("File system block switched to PC.");
    } else {
      Serial.println("File system block is already for PC.");
    }
  } else {
    Serial.println("Invalid mode. Use 'mcu' or 'pc'.");
  }
}
// 查询当前文件系统块状态
void queryFSStatus() {
  if (fsForPC) {
    Serial.println("File system block is currently used by PC.");
  } else {
    Serial.println("File system block is currently used by MCU.");
  }
}

void generateAesKey(String password, uint8_t* aesKey, size_t keyLength) {
  // 固定盐值
  const char* salt = "rp2350";

  // 将密码与盐组合
  String combined = password + salt;

  // 生成 SHA-1 哈希
  uint8_t hash[HASH_SIZE];  // SHA-1 输出 20 字节
  sha1(combined.c_str(), hash);

  // 从哈希值中截取 AES 密钥
  memcpy(aesKey, hash, keyLength);
}

void encryptDatabase() {
  //Serial.println("Enter a password for encryption:");

  // 等待用户输入密码
  String userPassword;

  userPassword = rawPasswd;  // 去掉空格和换行符

  // 检查密码长度
  if (userPassword.length() == 0) {
    //Serial.println("Password cannot be empty.");
    return;
  }

  // 自动生成 AES 密钥
  uint8_t aesKey[16];  // 使用 128 位 AES
  generateAesKey(userPassword, aesKey, sizeof(aesKey));

  // 数据库文件路径
  const char* inputFile = "passwords.csv";
  const char* processedFile = "processed.csv";  // 临时文件
  const char* outputFile = "passwords.enc";

  // 检查原始文件是否存在
  if (!FatFS.exists(inputFile)) {
    Serial.println("Database file not found.");
    return;
  }

  // 处理数据库文件，仅保留目标列
  if (!processDatabase(inputFile, processedFile)) {
    Serial.println("Failed to process database file.");
    return;
  }

  // 加密处理后的文件
  if (encryptFile(processedFile, outputFile, aesKey, sizeof(aesKey))) {
    Serial.println("Database encrypted successfully!");
  } else {
    Serial.println("Failed to encrypt the database.");
  }

  // 删除临时文件
  FatFS.remove(processedFile);
}





void querySite(String site) {
  if (site.length() == 0) {
    Serial.println("Please provide a website name to query.");
    return;
  }

  // 将查询关键词转换为小写
  site.toLowerCase();

  // 加密文件名
  const char* encryptedFile = "passwords.enc";
  const char* decryptedFile = "passwords.tmp";

  // 解密文件
  uint8_t aesKey[16];  // AES 密钥
  String password;
  password = rawPasswd;

  if (password.length() == 0) {
    Serial.println("Password cannot be empty.");
    return;
  }

  // 生成 AES 密钥
  generateAesKey(password, aesKey, sizeof(aesKey));

  // 解密文件
  if (!decryptFile(encryptedFile, decryptedFile, aesKey, sizeof(aesKey))) {
    Serial.println("Failed to decrypt the database. Check your password.");
    return;
  }
  //previewDecryptedFile(decryptedFile, 5);
  // 打开解密后的文件并查询
  File dbFile = FatFS.open(decryptedFile, "r");
  if (!dbFile) {
    Serial.println("Failed to open the decrypted database.");
    return;
  }

  Serial.printf("Searching for websites containing: %s\n", site.c_str());
  bool found = false;

  while (dbFile.available()) {
    String line = dbFile.readStringUntil('\n');
    line.trim();
    if (line.startsWith("\"")) {  // CSV 数据格式
      int urlStart = line.indexOf('"') + 1;
      int urlEnd = line.indexOf('"', urlStart);
      String url = line.substring(urlStart, urlEnd);

      // 将被搜索的 URL 转换为小写
      String lowerUrl = url;
      lowerUrl.toLowerCase();

      // 检查是否部分匹配
      if (lowerUrl.indexOf(site) != -1) {  // 部分匹配
        // 提取用户名和密码
        int userStart = line.indexOf('"', urlEnd + 2) + 1;
        int userEnd = line.indexOf('"', userStart);
        String username = line.substring(userStart, userEnd);

        int passStart = line.indexOf('"', userEnd + 2) + 1;
        int passEnd = line.indexOf('"', passStart);
        String password = line.substring(passStart, passEnd);

        // 显示结果
        Serial.println("=== Query Result ===");
        Serial.printf("Website : %s\n", url.c_str());
        Serial.printf("Username: %s\n", username.c_str());
        Serial.printf("Password: %s\n", password.c_str());
        Serial.println("====================");

        found = true;
      }
    }
  }

  dbFile.close();

  if (!found) {
    Serial.println("No entries found matching the specified keyword.");
  }

  // 删除临时解密文件
  FatFS.remove(decryptedFile);
}
void previewDecryptedFile(const char* filePath, int maxLines) {
  File file = FatFS.open(filePath, "r");
  if (!file) {
    Serial.println("Failed to open decrypted file for preview.");
    return;
  }

  Serial.println("Preview of decrypted file:");
  int lineCount = 0;

  while (file.available() && lineCount < maxLines) {
    String line = file.readStringUntil('\n');
    Serial.println(line);
    lineCount++;
  }

  file.close();
}

bool encryptFile(const char* inputFile, const char* outputFile, uint8_t* aesKey, size_t keyLength) {
  AES aes;  // 创建 AES 对象

  // 初始化 AES 密钥
  aes.set_key(aesKey, keyLength);  // 参数 1: 密钥，参数 2: 密钥长度（字节）

  // 生成随机 IV
  uint8_t iv[16];
  generateRandomIV(iv, sizeof(iv));

  // 打开输入文件（只读）和输出文件（写入）
  File inFile = FatFS.open(inputFile, "r");
  File outFile = FatFS.open(outputFile, "w");
  if (!inFile || !outFile) {
    Serial.println("Failed to open input or output file!");
    return false;
  }

  // 写入 IV 到输出文件的开头
  outFile.write(iv, sizeof(iv));

  uint8_t buffer[16];     // 数据块缓冲区（16 字节）
  uint8_t encrypted[16];  // 加密后的数据缓冲区
  size_t bytesRead;

  while ((bytesRead = inFile.read(buffer, sizeof(buffer))) > 0) {
    // 如果读取的数据不足 16 字节，使用 PKCS#7 填充
    if (bytesRead < sizeof(buffer)) {
      for (size_t i = bytesRead; i < sizeof(buffer); i++) {
        buffer[i] = sizeof(buffer) - bytesRead;
      }
    }

    // 加密当前块数据
    aes.do_aes_encrypt(buffer, sizeof(buffer), encrypted, aesKey, 128, iv);

    // 写入加密数据到输出文件
    outFile.write(encrypted, sizeof(encrypted));
  }

  inFile.close();   // 关闭输入文件
  outFile.close();  // 关闭输出文件
  return true;      // 加密成功
}
bool decryptFile(const char* inputFile, const char* outputFile, uint8_t* aesKey, size_t keyLength) {
  AES aes;  // 创建 AES 对象

  // 打开输入文件（只读）和输出文件（写入）
  File inFile = FatFS.open(inputFile, "r");
  File outFile = FatFS.open(outputFile, "w");
  if (!inFile || !outFile) {
    Serial.println("Failed to open input or output file!");
    return false;
  }

  // 从文件头部读取 IV
  uint8_t iv[16];
  if (inFile.read(iv, sizeof(iv)) != sizeof(iv)) {
    Serial.println("Failed to read IV from encrypted file.");
    inFile.close();
    outFile.close();
    return false;
  }

  uint8_t buffer[16];
  uint8_t decrypted[16];
  size_t bytesRead;

  while ((bytesRead = inFile.read(buffer, sizeof(buffer))) > 0) {
    // 解密当前块数据
    aes.do_aes_decrypt(buffer, sizeof(buffer), decrypted, aesKey, 128, iv);

    // 如果是最后一块数据，移除 PKCS#7 填充
    if (inFile.available() == 0) {            // 文件读取到末尾
      bytesRead -= decrypted[bytesRead - 1];  // 去掉填充
    }

    // 写入解密数据到输出文件
    outFile.write(decrypted, bytesRead);
  }

  inFile.close();   // 关闭输入文件
  outFile.close();  // 关闭输出文件
  return true;      // 解密成功
}
void generateRandomIV(uint8_t* iv, size_t length) {
  for (size_t i = 0; i < length; i++) {
    iv[i] = random(0, 256);  // 生成 0-255 范围内的随机字节
  }
}


void listFiles(const char* directory) {
  // 确保 MCU 控制存储块
  if (fsForPC) {
    Serial.println("Error: File system block is currently controlled by PC. Switch to MCU control to use 'ls'.");
    return;
  }

  // 打开目录
  Dir dir = FatFS.openDir(directory);


  Serial.printf("Listing files in directory: %s\n", directory);
  while (dir.next()) {
    // 打印文件名
    Serial.print(dir.fileName());
    if (dir.isDirectory()) {
      Serial.println("/");  // 标记目录
    } else {
      // 打印文件大小和创建时间
      Serial.print("\t");
      Serial.print(dir.fileSize(), DEC);

      time_t cr = dir.fileCreationTime();
      struct tm* tmstruct = localtime(&cr);
      Serial.printf("\t%d-%02d-%02d %02d:%02d:%02d\n",
                    (tmstruct->tm_year) + 1900,
                    (tmstruct->tm_mon) + 1,
                    tmstruct->tm_mday,
                    tmstruct->tm_hour,
                    tmstruct->tm_min,
                    tmstruct->tm_sec);
    }
  }
}

void removeFile(const char* filePath) {
  // 确保 MCU 控制存储块
  if (fsForPC) {
    Serial.println("Error: File system block is currently controlled by PC. Switch to MCU control to use 'rm'.");
    return;
  }

  // 检查文件是否存在
  if (!FatFS.exists(filePath)) {
    Serial.printf("Error: File '%s' does not exist.\n", filePath);
    return;
  }

  // 删除文件
  if (FatFS.remove(filePath)) {
    Serial.printf("File '%s' removed successfully.\n", filePath);
  } else {
    Serial.printf("Failed to remove file '%s'.\n", filePath);
  }
}


// 清空内存和保存数据的函数
void safeExit() {
  Serial.println("Saving data...");

  // 保存所有必要的数据到 EEPROM 或文件
  EEPROM.commit();
  Serial.println("Data saved successfully.");

  // 清理内存
  Serial.println("Clearing memory...");
  // 如果有动态内存分配，手动释放内存
  // 示例：free(pointer); 或清空全局变量
  // 如无动态分配，可跳过此步骤
  // 显示内存状态
  Serial.printf("Free Heap: %d bytes\n", rp2040.getFreeHeap());
  Serial.printf("Used Heap: %d bytes\n", rp2040.getUsedHeap());
  Serial.println("Memory cleared.");

  // 停止所有运行的任务或服务
  Serial.println("Stopping services...");
  FatFS.end();     // 关闭文件系统
  FatFSUSB.end();  // 关闭 USB 文件共享
  Serial.println("Services stopped.");

  // 提示用户可以安全关机
  Serial.println("System is now ready for shutdown. Please turn off the power.");

  // 停止程序运行
  while (true) {
    delay(100);  // 等待用户断电
  }
}
bool processDatabase(const char* inputFile, const char* outputFile) {
  File inFile = FatFS.open(inputFile, "r");
  File outFile = FatFS.open(outputFile, "w");

  if (!inFile || !outFile) {
    Serial.println("Failed to open input or output file for processing.");
    return false;
  }

  while (inFile.available()) {
    String line = inFile.readStringUntil('\n');
    line.trim();  // 移除行首和行尾的多余空格和换行符

    if (line.length() > 0 && line.startsWith("\"")) {
      // 按逗号分隔列
      int urlStart = line.indexOf('"') + 1;
      int urlEnd = line.indexOf('"', urlStart);
      String url = line.substring(urlStart, urlEnd);

      int userStart = line.indexOf('"', urlEnd + 2) + 1;
      int userEnd = line.indexOf('"', userStart);
      String username = line.substring(userStart, userEnd);

      int passStart = line.indexOf('"', userEnd + 2) + 1;
      int passEnd = line.indexOf('"', passStart);
      String password = line.substring(passStart, passEnd);

      // 写入保留的三列到输出文件
      outFile.printf("\"%s\",\"%s\",\"%s\"\n", url.c_str(), username.c_str(), password.c_str());
    }
  }

  inFile.close();
  outFile.close();
  return true;
}
void appendToEncryptedDatabase(const char* url, const char* username, const char* password) {
  // 数据库文件名
  const char* encryptedFile = "passwords.enc";
  const char* tempFile = "passwords.tmp";

  // 解密文件到临时文件
  uint8_t aesKey[16];
  generateAesKey(rawPasswd.c_str(), aesKey, sizeof(aesKey));
  if (!decryptFile(encryptedFile, tempFile, aesKey, sizeof(aesKey))) {
    Serial.println("Failed to decrypt the database. Creating a new one.");
    // 如果解密失败，初始化空文件
    File temp = FatFS.open(tempFile, "w");
    if (!temp) {
      Serial.println("Failed to create a temporary file.");
      return;
    }
    temp.close();
  }

  // 打开临时文件进行检查
  File temp = FatFS.open(tempFile, "r+");
  if (!temp) {
    Serial.println("Failed to open the temporary file.");
    return;
  }

  // 确保文件指针在文件末尾，以追加新记录
  temp.seek(temp.size());

  // 追加新记录，格式为 CSV
  temp.printf("\"%s\",\"%s\",\"%s\"\n", url, username, password);
  temp.close();

  // 重新加密文件
  if (!encryptFile(tempFile, encryptedFile, aesKey, sizeof(aesKey))) {
    Serial.println("Failed to re-encrypt the database.");
    return;
  }

  // 删除临时文件
  FatFS.remove(tempFile);

  Serial.println("New entry added to the database successfully!");
}


void resetSystem() {
  Serial.println("Performing system reset...");

  // 清除 EEPROM 数据
  clearEEPROM();

  // 清除 Flash 文件系统
  clearFlash();

  // 重启系统
  rebootSystem();
}

// 清除 EEPROM 内容
void clearEEPROM() {
  Serial.println("Clearing EEPROM...");
  for (int i = 0; i < EEPROM_SIZE; i++) {
    EEPROM.write(i, 0xFF);  // 恢复到未写入状态
  }
  EEPROM.commit();
  Serial.println("EEPROM cleared.");
}

void clearFlash() {
  Serial.println("Clearing Flash...");
  Dir root = FatFS.openDir("/");

  while (root.next()) {
    if (root.isDirectory()) {
      // 如果是目录，递归删除
      clearDirectory(root.fileName().c_str());  // 修正：将 String 转换为 const char*
    } else {
      // 删除文件
      if (FatFS.remove(root.fileName().c_str())) {  // 修正：将 String 转换为 const char*
        Serial.printf("Deleted file: %s\n", root.fileName().c_str());
      } else {
        Serial.printf("Failed to delete file: %s\n", root.fileName().c_str());
      }
    }
  }
  Serial.println("Flash cleared.");
}

// 定义 clearDirectory 函数
void clearDirectory(const char* dirPath) {
  Serial.printf("Clearing directory: %s\n", dirPath);

  Dir dir = FatFS.openDir(dirPath);
  while (dir.next()) {
    if (dir.isDirectory()) {
      // 递归清空子目录
      clearDirectory(dir.fileName().c_str());
    } else {
      // 删除文件
      if (FatFS.remove(dir.fileName().c_str())) {
        Serial.printf("Deleted file: %s\n", dir.fileName().c_str());
      } else {
        Serial.printf("Failed to delete file: %s\n", dir.fileName().c_str());
      }
    }
  }

  // 删除空目录
  if (FatFS.rmdir(dirPath)) {
    Serial.printf("Deleted directory: %s\n", dirPath);
  } else {
    Serial.printf("Failed to delete directory: %s\n", dirPath);
  }
}
void rebootSystem() {
  Serial.println("Rebooting system...");
  delay(1000);  // 等待一段时间以供用户查看提示
  rp2040.reboot();
}


// 函数：Base32 解码
void base32Decode(const char* encoded, uint8_t* decoded, size_t& decodedLen) {
  size_t buffer = 0;
  int bitsLeft = 0;
  size_t index = 0;

  for (size_t i = 0; encoded[i] != '\0'; i++) {
    char c = toupper(encoded[i]);
    if (c >= 'A' && c <= 'Z') {
      buffer = (buffer << 5) | (c - 'A');
    } else if (c >= '2' && c <= '7') {
      buffer = (buffer << 5) | (c - '2' + 26);
    } else {
      continue; // 跳过非法字符
    }
    bitsLeft += 5;

    if (bitsLeft >= 8) {
      decoded[index++] = (buffer >> (bitsLeft - 8)) & 0xFF;
      bitsLeft -= 8;
    }
  }
  decodedLen = index;
}

int generateTOTP(unsigned long time, const char* base32Secret) {
    uint8_t key[64];
    size_t keyLen = 0;
    base32Decode(base32Secret, key, keyLen);

    // 计算时间步长
    unsigned long timeCounter = time / TIME_STEP;

    // 转换时间步长为大端字节序
    uint8_t timeBytes[8] = {0};
    for (int i = 7; i >= 0; i--) {
        timeBytes[i] = timeCounter & 0xFF;
        timeCounter >>= 8;
    }

    // 使用 HMAC-SHA1 计算哈希
    uint8_t hash[20];
    hmac_sha1(key, keyLen, timeBytes, sizeof(timeBytes), hash);

    // 动态截取
    int offset = hash[19] & 0x0F;
    int binaryCode = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);

    return binaryCode % 1000000; // 6 位 TOTP
}

// 创建新 TOTP Token
void createTOTP(const char* tag, const char* base32Secret) {
  TOTPToken token;

  // 填充 TOTPToken 的数据
  strncpy(token.tag, tag, sizeof(token.tag) - 1);
  strncpy(token.base32Secret, base32Secret, sizeof(token.base32Secret) - 1);

  // 读取当前令牌数量
  int count = EEPROM.read(EEPROM_OFFSET); // 从偏移地址读取 count

  // 计算新令牌的存储地址
  int address = count * sizeof(TOTPToken) + EEPROM_OFFSET + 1;

  // 将新令牌写入 EEPROM
  EEPROM.put(address, token);

  // 更新令牌数量
  EEPROM.write(EEPROM_OFFSET, count + 1);
  EEPROM.commit();

  Serial.printf("TOTP created for tag: %s\n", tag);
}

// 从 EEPROM 中加载 TOTP Token
TOTPToken loadTOTP(const char* tag) {
  TOTPToken token;
  int count = EEPROM.read(EEPROM_OFFSET); // 从偏移地址读取 count

  // 遍历每个令牌
  for (int i = 0; i < count; i++) {
    int address = i * sizeof(TOTPToken) + EEPROM_OFFSET + 1;
    EEPROM.get(address, token); // 从偏移地址读取令牌数据

    // 如果找到匹配的 tag，返回该令牌
    if (strcmp(token.tag, tag) == 0) {
      return token;
    }
  }

  // 未找到，返回空令牌
  TOTPToken emptyToken = {"", ""};
  return emptyToken;
}

// 生成 TOTP
void generateTOTPCode(const char* tag, unsigned long time) {
  TOTPToken token = loadTOTP(tag);

  if (strlen(token.tag) == 0) {
    Serial.println("TOTP not found for this tag.");
    return;
  }

  int totpCode = generateTOTP(time, token.base32Secret);
  Serial.printf("TOTP for tag '%s': %06d\n", tag, totpCode);
}

// 时间字符串解析函数
unsigned long parseStandardTime(const char* timeStr) {
  struct tm timeinfo;
  sscanf(timeStr, "%4d/%2d/%2d/%2d/%2d/%2d",
         &timeinfo.tm_year, &timeinfo.tm_mon, &timeinfo.tm_mday,
         &timeinfo.tm_hour, &timeinfo.tm_min, &timeinfo.tm_sec);
  timeinfo.tm_year -= 1900;
  timeinfo.tm_mon -= 1;
  return mktime(&timeinfo);
}

void handleTOTPCommand(String command) {
  command.trim();
  if (command.startsWith("create_totp")) {
    int firstComma = command.indexOf(',');
    int secondComma = command.indexOf(',', firstComma + 1);

    String tag = command.substring(firstComma + 1, secondComma);
    String secret = command.substring(secondComma + 1);

    createTOTP(tag.c_str(), secret.c_str());
  } else if (command.startsWith("generate_totp")) {
    int comma = command.indexOf(',');
    String tag = command.substring(13, comma);
    String timeStr = command.substring(comma + 1);

    unsigned long time = parseStandardTime(timeStr.c_str());
    generateTOTPCode(tag.c_str(), time);
  } else {
    Serial.println("Invalid TOTP command.");
  }
}


void hmac_sha1(const uint8_t* key, size_t keyLen, const uint8_t* message, size_t messageLen, uint8_t* outHash) {
    // 定义常量
    const size_t BLOCK_SIZE = 64; // SHA1 的块大小为 64 字节
    uint8_t ipad[BLOCK_SIZE];    // 内部填充
    uint8_t opad[BLOCK_SIZE];    // 外部填充
    uint8_t keyPad[BLOCK_SIZE];  // 填充后的密钥
    uint8_t innerHash[20];       // 内部哈希结果

    // 初始化 keyPad，填充到 BLOCK_SIZE
    memset(keyPad, 0, BLOCK_SIZE);
    if (keyLen > BLOCK_SIZE) {
        // 如果 key 长度大于 BLOCK_SIZE，则先对 key 取 sha1 哈希
        sha1(key, keyLen, keyPad);
    } else {
        // 否则直接复制 key 到 keyPad
        memcpy(keyPad, key, keyLen);
    }

    // 初始化 ipad 和 opad
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = keyPad[i] ^ 0x36; // 按位异或
        opad[i] = keyPad[i] ^ 0x5C; // 按位异或
    }

    // 计算内部哈希：SHA1(ipad || message)
    uint8_t innerData[BLOCK_SIZE + messageLen];
    memcpy(innerData, ipad, BLOCK_SIZE);
    memcpy(innerData + BLOCK_SIZE, message, messageLen);
    sha1(innerData, BLOCK_SIZE + messageLen, innerHash);

    // 计算外部哈希：SHA1(opad || innerHash)
    uint8_t outerData[BLOCK_SIZE + 20]; // 20 字节是 SHA1 输出大小
    memcpy(outerData, opad, BLOCK_SIZE);
    memcpy(outerData + BLOCK_SIZE, innerHash, 20);
    sha1(outerData, BLOCK_SIZE + 20, outHash);
}