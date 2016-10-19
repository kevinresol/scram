package ;

import scram.*;
import haxe.unit.*;

class RunTests extends TestCase {

  static function main() {
    var runner = new TestRunner();
    runner.add(new RunTests());
    travix.Logger.exit(runner.run() ? 0 : 500);
  }
  
  function testSha256() {
    var scram = new ScramClient('user', 'pencil', SHA256, 'fyko+d2lbbFgONRv9qkxdawL');
    assertEquals('n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL', scram.clientFirstMessage);
    scram.serverFirstMessage = 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096';
    assertEquals('c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=qQRLRHGPDGjB+7iVAE7NNi5xEoHKHuLCHPNQ8BTmvds=', scram.clientFinalMessage);
    scram.serverFinalMessage = 'v=XKW6VuW1FANROQabnJBz1KaeCnQL/HZByQtX/iU+o30=';
  }
  
  function testSha1() {
    var scram = new ScramClient('user', 'pencil', SHA1, 'fyko+d2lbbFgONRv9qkxdawL');
    assertEquals('n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL', scram.clientFirstMessage);
    scram.serverFirstMessage = 'r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096';
    assertEquals('c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=', scram.clientFinalMessage);
    scram.serverFinalMessage = 'v=rmF9pqV8S7suAoZWja4dJRkFsKQ=';
  }
}
