<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security;

use SensioLabs\Security\Exception\RuntimeException;
use SensioLabs\Security\Crawler\CrawlerInterface;
use SensioLabs\Security\Crawler\DefaultCrawler;

class SecurityChecker
{
    const VERSION = '4';

    private $vulnerabilityCount;
    private $crawler;

    public function __construct(CrawlerInterface $crawler = null)
    {
        $this->crawler = null === $crawler ? new DefaultCrawler() : $crawler;
    }

    /**
     * Checks a composer.lock file.
     *
     * @param string $lock The path to the composer.lock file
     *
     * @return array An array of vulnerabilities
     *
     * @throws RuntimeException When the lock file does not exist
     * @throws RuntimeException When the certificate can not be copied
     */
    public function check($lock)
    {
        if (is_dir($lock) && file_exists($lock.'/composer.lock')) {
            $lock = $lock.'/composer.lock';
        } elseif (preg_match('/composer\.json$/', $lock)) {
            $lock = str_replace('composer.json', 'composer.lock', $lock);
        }

        if (!is_file($lock)) {
            throw new RuntimeException('Lock file does not exist.');
        }

        $configFile = str_replace('composer.lock', 'securityChecker.json', $lock);

        $check = $this->crawler->check($lock);

        if (is_file($configFile)) {
            $exclusions = $this->getSecurityExclusions($configFile);
            $check      = $this->removeExclusions($check, $exclusions);
        }

        list($this->vulnerabilityCount, $vulnerabilities) = $check;

        return $vulnerabilities;
    }

    public function getLastVulnerabilityCount()
    {
        return $this->vulnerabilityCount;
    }

    /**
     * @return CrawlerInterface
     */
    public function getCrawler()
    {
        return $this->crawler;
    }

    /**
     * Retrieves list of exclusions from external config file.
     *
     * @param string $configFile The path to the securityChecker.json file
     *
     * @return array An array of vulnerabilities to exclude
     */
    private function getSecurityExclusions($configFile)
    {
        try {
            $config = json_decode(file_get_contents($configFile), true);

            if ($config['exclusions'] && is_array($config['exclusions'])) {
                return $config['exclusions'];
            }
        } catch (\Exception $e) {
            throw new RuntimeException('Config file does not contain valid json.');
        }

        return [];
    }

    /**
     * Removes specified exclusions from the checks.
     *
     * @param array $check      Security check results
     * @param array $exclusions CVEs / links to remove
     *
     * @return array Filtered list of vulnerabilities
     */
    private function removeExclusions($check, $exclusions)
    {
        foreach ($check[1] as $entryKey => $entry) {
            foreach ($entry['advisories'] as $advisoryKey => $advisory) {
                if (
                    (isset($advisory['link']) && in_array($advisory['link'], $exclusions)) ||
                    (isset($advisory['cve']) && in_array($advisory['cve'], $exclusions))
                ) {
                    unset($entry['advisories'][$advisoryKey]);
                }
            }

            if (count($entry['advisories']) === 0) {
                unset($check[1][$entryKey]);
            }
        };

        $check[0] = count($check[1]);

        return $check;
    }
}
