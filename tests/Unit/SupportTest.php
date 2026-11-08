<?php

declare(strict_types=1);

namespace Ctrlweb\SitePortrait\Tests\Unit;

use Ctrlweb\SitePortrait\Protocol\IpAllowlist;
use Ctrlweb\SitePortrait\Protocol\StructuredFields;
use Ctrlweb\SitePortrait\Support\Bytes;
use Ctrlweb\SitePortrait\Support\DirectorySize;
use Ctrlweb\SitePortrait\Support\SystemInfo;
use PHPUnit\Framework\TestCase;

final class SupportTest extends TestCase
{
    public function test_structured_fields_parse_and_serialize(): void
    {
        $input = 'sp=("@method" "@path");created=1;nonce="a\\"b";alg="ed25519", other=:AAEC:;x';
        $dict = StructuredFields::parseDictionary($input);
        $this->assertNotNull($dict);
        $this->assertSame('inner_list', $dict['sp']['type']);
        $this->assertSame('a"b', $dict['sp']['params']['nonce']['value']);
        $this->assertSame("\x00\x01\x02", $dict['other']['value']);
        $this->assertTrue($dict['other']['params']['x']['value']);
        $this->assertSame('("@method" "@path");created=1;nonce="a\\"b";alg="ed25519"', StructuredFields::serializeInnerList($dict['sp']['value'], $dict['sp']['params']));

        foreach (['sp=(', 'sp=("a" "b"', 'sp="unterminated', 'sp=:not base64!:', 'SP=1', 'sp=1,', "sp=\"\x01\""] as $bad) {
            $this->assertNull(StructuredFields::parseDictionary($bad), $bad);
        }
        $this->assertNull(StructuredFields::parseDictionary(null));
    }

    public function test_ip_allowlist(): void
    {
        $entries = ['192.0.2.0/24', '2001:db8::/32', '198.51.100.7', 'garbage'];
        $this->assertTrue(IpAllowlist::matches('192.0.2.200', $entries));
        $this->assertTrue(IpAllowlist::matches('2001:db8:1::1', $entries));
        $this->assertTrue(IpAllowlist::matches('198.51.100.7', $entries));
        $this->assertFalse(IpAllowlist::matches('198.51.100.8', $entries));
        $this->assertFalse(IpAllowlist::matches('2001:db9::1', $entries));
        $this->assertFalse(IpAllowlist::matches('not-an-ip', $entries));
        $this->assertTrue(IpAllowlist::matches('203.0.113.5', ['203.0.113.0/29']));
        $this->assertFalse(IpAllowlist::matches('203.0.113.9', ['203.0.113.0/29']));
        $this->assertFalse(IpAllowlist::isValidEntry('10.0.0.0/33'));
    }

    public function test_ini_bytes(): void
    {
        $this->assertSame(128 * 1024 * 1024, Bytes::fromIni('128M'));
        $this->assertSame(2 * 1024 ** 3, Bytes::fromIni('2G'));
        $this->assertSame(512, Bytes::fromIni('512'));
        $this->assertNull(Bytes::fromIni('-1'));
        $this->assertNull(Bytes::fromIni('lots'));
    }

    public function test_cgroup_v2_container(): void
    {
        $info = new SystemInfo(__DIR__.'/../fixtures/proc-v2');
        $cpu = $info->cpu();
        $this->assertSame(2, $cpu['count']);
        $this->assertSame('AMD EPYC 7763 64-Core Processor', $cpu['model']);
        $this->assertSame(1.5, $cpu['cgroup_quota']);

        $memory = $info->memory();
        $this->assertSame(16303428 * 1024, $memory['total']);
        $this->assertSame(8000000 * 1024, $memory['available']);
        $this->assertSame(2097148 * 1024, $memory['swap_total']);
        $this->assertSame(2147483648, $memory['cgroup_limit']);
        $this->assertTrue($info->containerized());
    }

    public function test_cgroup_v1_unlimited(): void
    {
        $info = new SystemInfo(__DIR__.'/../fixtures/proc-v1');
        $this->assertNull($info->cgroupCpuQuota());
        $this->assertNull($info->cgroupMemoryLimit());
        $this->assertNull($info->cpu()['count']);
        $this->assertNull($info->memory()['total']);
    }

    public function test_directory_size_counts_regular_files_without_following_links(): void
    {
        $root = sys_get_temp_dir().'/sp-dirsize-'.bin2hex(random_bytes(4));
        mkdir($root.'/sub/deeper', 0777, true);
        file_put_contents($root.'/a.txt', '12345');
        file_put_contents($root.'/sub/b.txt', '123');
        file_put_contents($root.'/sub/deeper/c.txt', '1');
        symlink($root.'/a.txt', $root.'/link.txt');
        symlink($root.'/sub', $root.'/linked-dir');

        try {
            $budget = new DirectorySize(10);
            $this->assertSame(['size' => 9, 'files' => 3, 'timeout' => false], $budget->measure($root));
            $this->assertSame(['size' => null, 'files' => null, 'timeout' => false], $budget->measure($root.'/linked-dir'));
            $this->assertSame(['size' => null, 'files' => null, 'timeout' => false], $budget->measure($root.'/missing'));
            $this->assertSame(['size' => null, 'files' => null, 'timeout' => true], (new DirectorySize(0))->measure($root));
        } finally {
            unlink($root.'/link.txt');
            unlink($root.'/linked-dir');
            unlink($root.'/sub/deeper/c.txt');
            unlink($root.'/sub/b.txt');
            unlink($root.'/a.txt');
            rmdir($root.'/sub/deeper');
            rmdir($root.'/sub');
            rmdir($root);
        }
    }

    public function test_missing_root(): void
    {
        $this->assertNull((new SystemInfo(__DIR__.'/../fixtures/does-not-exist'))->containerized());
    }
}
