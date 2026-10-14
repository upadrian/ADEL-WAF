<?php

declare(strict_types=1);

namespace AdelWAF\Tests;

use AdelWAF\Scanner\MalwareScanner;

final class ScannerTest extends TestCase
{
    public function testFindsShellsAndIgnoresCleanCode(): void
    {
        mkdir($this->tmp . '/site/sub', 0777, true);
        file_put_contents($this->tmp . '/site/clean.php', "<?php\nfunction add(\$a, \$b) { return \$a + \$b; }\necho add(1, 2);\n");
        file_put_contents($this->tmp . '/site/sub/evil.php', '<?php @eval(base64_decode($_POST["x"]));');
        file_put_contents($this->tmp . '/site/sub/cmd.php', '<?php system($_GET["c"]);');
        file_put_contents($this->tmp . '/site/c99.php', '<html><title>r57 shell</title></html>');
        file_put_contents($this->tmp . '/site/notes.txt', '<?php eval(base64_decode($_POST["x"]));');

        $hits = (new MalwareScanner())->scan($this->tmp . '/site');
        $files = array_map(fn ($h) => basename($h['file']), $hits);
        sort($files);
        $this->assertSame(['c99.php', 'cmd.php', 'evil.php'], $files);
    }
}
