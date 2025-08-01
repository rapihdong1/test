<?php
/**
 * Antibot Protection Script with cURL
 * Blocks bots, crawlers, and suspicious IP addresses
 * Usage: require_once 'antibot.php'; at the top of your main page
 */

class AntibotProtection {
    
    private $blockedKeywords = [
        'facebook',
        'meta',
        'google',
        'amazon',
        'microsoft',
        'digitalocean',
        'vultr',
        'linode',
        'ovh',
        'hetzner',
        'cloudflare'
    ];
    
    private $botPatterns = [
        'Googlebot', 'Googlebot-Mobile', 'Googlebot-Image', 'Googlebot-News', 'Googlebot-Video',
        'AdsBot-Google', 'Feedfetcher-Google', 'Mediapartners-Google', 'APIs-Google',
        'Google-InspectionTool', 'Storebot-Google', 'GoogleOther', 'bingbot', 'Slurp',
        'wget', 'LinkedInBot', 'Python-urllib', 'python-requests', 'aiohttp', 'httpx',
        'libwww-perl', 'httpunit', 'Nutch', 'Go-http-client', 'phpcrawl', 'msnbot',
        'jyxobot', 'FAST-WebCrawler', 'BIGLOTRON', 'Teoma', 'convera', 'seekbot',
        'Gigabot', 'Gigablast', 'exabot', 'ia_archiver', 'GingerCrawler', 'webmon',
        'HTTrack', 'grub.org', 'UsineNouvelleCrawler', 'antibot', 'netresearchserver',
        'speedy', 'fluffy', 'findlink', 'msrbot', 'panscient', 'yacybot', 'AISearchBot',
        'ips-agent', 'tagoobot', 'MJ12bot', 'woriobot', 'yanga', 'buzzbot', 'mlbot',
        'yandex.com/bots', 'purebot', 'Linguee Bot', 'CyberPatrol', 'voilabot',
        'Baiduspider', 'citeseerxbot', 'spbot', 'twengabot', 'postrank', 'Turnitin',
        'scribdbot', 'page2rss', 'sitebot', 'linkdex', 'Adidxbot', 'ezooms', 'dotbot',
        'Mail.RU_Bot', 'discobot', 'heritrix', 'findthatfile', 'europarchive.org',
        'NerdByNature.Bot', 'sistrix', 'SISTRIX', 'AhrefsBot', 'AhrefsSiteAudit',
        'fuelbot', 'CrunchBot', 'IndeedBot', 'mappydata', 'woobot', 'ZoominfoBot',
        'PrivacyAwareBot', 'Multiviewbot', 'SWIMGBot', 'Grobbot', 'eright', 'Apercite',
        'semanticbot', 'Aboundex', 'domaincrawler', 'wbsearchbot', 'summify', 'CCBot',
        'edisterbot', 'SeznamBot', 'ec2linkfinder', 'gslfbot', 'aiHitBot', 'intelium_bot',
        'facebookexternalhit', 'Yeti', 'RetrevoPageAnalyzer', 'lb-spider', 'Sogou',
        'lssbot', 'careerbot', 'wotbox', 'wocbot', 'ichiro', 'DuckDuckBot',
        'lssrocketcrawler', 'drupact', 'webcompanycrawler', 'acoonbot', 'openindexspider',
        'gnam gnam spider', 'web-archive-net.com.bot', 'backlinkcrawler', 'coccoc',
        'integromedb', 'content crawler spider', 'toplistbot', 'it2media-domain-crawler',
        'ip-web-crawler.com', 'siteexplorer.info', 'elisabot', 'proximic',
        'changedetection', 'arabot', 'WeSEE:Search', 'niki-bot', 'CrystalSemanticsBot',
        'rogerbot', '360Spider', 'psbot', 'InterfaxScanBot', 'CC Metadata Scaper',
        'g00g1e.net', 'GrapeshotCrawler', 'urlappendbot', 'brainobot', 'fr-crawler',
        'binlar', 'SimpleCrawler', 'Twitterbot', 'cXensebot', 'smtbot', 'bnf.fr_bot',
        'A6-Indexer', 'ADmantX', 'Facebot', 'OrangeBot', 'memorybot', 'AdvBot',
        'MegaIndex', 'SemanticScholarBot', 'ltx71', 'nerdybot', 'xovibot', 'BUbiNG',
        'Qwantify', 'archive.org_bot', 'Applebot', 'TweetmemeBot', 'crawler4j',
        'findxbot', 'SemrushBot', 'SEMrushBot', 'yoozBot', 'lipperhey', 'Y!J',
        'Domain Re-Animator Bot', 'AddThis', 'Screaming Frog SEO Spider', 'MetaURI',
        'Scrapy', 'Livelapbot', 'LivelapBot', 'OpenHoseBot', 'CapsuleChecker',
        'collection@infegy.com', 'IstellaBot', 'DeuSu', 'betaBot', 'Cliqzbot',
        'MojeekBot', 'netEstate NE Crawler', 'SafeSearch microdata crawler',
        'Gluten Free Crawler', 'Sonic', 'Sysomos', 'Trove', 'deadlinkchecker',
        'Slack-ImgProxy', 'Embedly', 'RankActiveLinkBot', 'iskanie', 'SafeDNSBot',
        'SkypeUriPreview', 'Veoozbot', 'Slackbot', 'redditbot', 'datagnionbot',
        'Google-Adwords-Instant', 'adbeat_bot', 'WhatsApp', 'contxbot', 'pinterest.com/bot',
        'electricmonk', 'GarlikCrawler', 'BingPreview', 'vebidoobot', 'FemtosearchBot',
        'Yahoo Link Preview', 'MetaJobBot', 'DomainStatsBot', 'mindUpBot', 'Daum',
        'Jugendschutzprogramm-Crawler', 'Xenu Link Sleuth', 'Pcore-HTTP', 'moatbot',
        'KosmioBot', 'Pingdom', 'pingdom', 'AppInsights', 'PhantomJS', 'Gowikibot',
        'PiplBot', 'Discordbot', 'TelegramBot', 'Jetslide', 'newsharecounts',
        'James BOT', 'Barkrowler', 'BarkRowler', 'TinEye', 'SocialRankIOBot',
        'trendictionbot', 'Ocarinabot', 'epicbot', 'Primalbot', 'DuckDuckGo-Favicons-Bot',
        'GnowitNewsbot', 'Leikibot', 'LinkArchiver', 'YaK', 'PaperLiBot', 'Digg Deeper',
        'dcrawl', 'Snacktory', 'AndersPinkBot', 'Fyrebot', 'EveryoneSocialBot',
        'Mediatoolkitbot', 'Luminator-robots', 'ExtLinksBot', 'SurveyBot', 'NING',
        'okhttp', 'Nuzzel', 'omgili', 'PocketParser', 'YisouSpider', 'um-LN',
        'ToutiaoSpider', 'MuckRack', 'Jamie\'s Spider', 'AHC', 'NetcraftSurveyAgent',
        'Laserlikebot', 'Apache-HttpClient', 'AppEngine-Google', 'Jetty', 'Upflow',
        'Thinklab', 'Traackr.com', 'Twurly', 'Mastodon', 'http_get', 'DnyzBot',
        'botify', '007ac9 Crawler', 'BehloolBot', 'BrandVerity', 'check_http',
        'BDCbot', 'ZumBot', 'EZID', 'ICC-Crawler', 'ArchiveBot', 'LCC',
        'filterdb.iss.net/crawler', 'BLP_bbot', 'BomboraBot', 'Buck', 'Companybook-Crawler',
        'Genieo', 'magpie-crawler', 'MeltwaterNews', 'Moreover', 'newspaper', 'ScoutJet',
        'sentry', 'StorygizeBot', 'UptimeRobot', 'OutclicksBot', 'seoscanners',
        'python-requests', 'Hatena', 'Google Web Preview', 'MauiBot', 'AlphaBot',
        'SBL-BOT', 'IAS crawler', 'adscanner', 'Netvibes', 'acapbot', 'Baidu-YunGuanCe',
        'bitlybot', 'blogmuraBot', 'Bot.AraTurka.com', 'bot-pge.chlooe.com', 'BoxcarBot',
        'BTWebClient', 'ContextAd Bot', 'Digincore bot', 'Disqus', 'Feedly', 'Fetch',
        'Fever', 'Flamingo_SearchEngine', 'FlipboardProxy', 'g2reader-bot',
        'G2 Web Services', 'imrbot', 'K7MLWCBot', 'Kemvibot', 'Landau-Media-Spider',
        'linkapediabot', 'vkShare', 'Siteimprove.com', 'BLEXBot', 'DareBoost',
        'ZuperlistBot', 'Miniflux', 'Feedspot', 'Diffbot', 'SEOkicks', 'tracemyfile',
        'Nimbostratus-Bot', 'zgrab', 'PR-CY.RU', 'AdsTxtCrawler', 'Datafeedwatch',
        'Zabbix', 'TangibleeBot', 'google-xrawler', 'axios', 'Amazon CloudFront',
        'Pulsepoint', 'CloudFlare', 'Cloudflare', 'Google-Structured-Data-Testing-Tool',
        'WordupInfoSearch', 'WebDataStats', 'HttpUrlConnection', 'ZoomBot',
        'VelenPublicWebCrawler', 'MoodleBot', 'jpg-newsbot', 'outbrain', 'W3C_Validator',
        'Validator.nu', 'W3C-checklink', 'W3C-mobileOK', 'W3C_I18n-Checker',
        'FeedValidator', 'W3C_CSS_Validator', 'W3C_Unicorn', 'Google-PhysicalWeb',
        'Blackboard', 'ICBot', 'BazQux', 'Twingly', 'Rivva', 'Experibot',
        'awesomecrawler', 'Dataprovider.com', 'GroupHigh', 'theoldreader.com',
        'AnyEvent', 'Uptimebot.org', 'Nmap Scripting Engine', '2ip.ru', 'Clickagy',
        'Caliperbot', 'MBCrawler', 'online-webceo-bot', 'B2B Bot', 'AddSearchBot',
        'Google Favicon', 'HubSpot', 'Chrome-Lighthouse', 'HeadlessChrome',
        'CheckMarkNetwork', 'www.uptime.com', 'Streamline3Bot', 'serpstatbot',
        'MixnodeCache', 'curl', 'SimpleScraper', 'RSSingBot', 'Jooblebot',
        'fedoraplanet', 'Friendica', 'NextCloud', 'Tiny Tiny RSS', 'RegionStuttgartBot',
        'Bytespider', 'Datanyze', 'Google-Site-Verification', 'TrendsmapResolver',
        'tweetedtimes', 'NTENTbot', 'Gwene', 'SimplePie', 'SearchAtlas', 'Superfeedr',
        'feedbot', 'UT-Dorkbot', 'Amazonbot', 'SerendeputyBot', 'Eyeotabot',
        'officestorebot', 'Neticle Crawler', 'SurdotlyBot', 'LinkisBot',
        'AwarioSmartBot', 'AwarioRssBot', 'RyteBot', 'FreeWebMonitoring SiteChecker',
        'AspiegelBot', 'NAVER Blog Rssbot', 'zenback bot', 'SentiBot',
        'Domains Project', 'Pandalytics', 'VKRobot', 'bidswitchbot', 'tigerbot',
        'NIXStatsbot', 'Atom Feed Robot', 'Curebot', 'curebot', 'PagePeeker',
        'Vigil', 'rssbot', 'startmebot', 'JobboerseBot', 'seewithkids', 'NINJA bot',
        'Cutbot', 'BublupBot', 'BrandONbot', 'RidderBot', 'Taboolabot', 'Dubbotbot',
        'FindITAnswersbot', 'infoobot', 'Refindbot', 'BlogTraffic', 'SeobilityBot',
        'Cincraw', 'Dragonbot', 'VoluumDSP-content-bot', 'FreshRSS', 'BitBot',
        'PHP-Curl-Class', 'Google-Certificates-Bridge', 'centurybot', 'Viber',
        'e.ventures Investment Crawler', 'evc-batch', 'PetalBot', 'virustotal',
        'PTST', 'minicrawler', 'Cookiebot', 'trovitBot', 'seostar.co', 'IonCrawl',
        'Uptime-Kuma', 'Seekport', 'FreshpingBot', 'Feedbin', 'CriteoBot',
        'Snap URL Preview Service', 'Better Uptime Bot', 'RuxitSynthetic',
        'Google-Read-Aloud', 'Valve/Steam', 'OdklBot', 'GPTBot', 'ChatGPT-User',
        'OAI-SearchBot', 'YandexRenderResourcesBot', 'LightspeedSystemsCrawler',
        'ev-crawler', 'BitSightBot', 'woorankreview', 'Google-Safety', 'AwarioBot',
        'DataForSeoBot', 'Linespider', 'WellKnownBot', 'A Patent Crawler', 'StractBot',
        'search.marginalia.nu', 'YouBot', 'Nicecrawler', 'Neevabot', 'BrightEdge Crawler',
        'SiteCheckerBotCrawler', 'TombaPublicWebCrawler', 'CrawlyProjectCrawler',
        'KomodiaBot', 'KStandBot', 'CISPA Webcrawler', 'MTRobot', 'hyscore.io',
        'AlexandriaOrgBot', '2ip bot', 'Yellowbrandprotectionbot', 'SEOlizer',
        'vuhuvBot', 'INETDEX-BOT', 'Synapse', 't3versionsBot', 'deepnoc',
        'Cocolyzebot', 'hypestat', 'ReverseEngineeringBot', 'sempi.tech', 'Iframely',
        'MetaInspector', 'node-fetch', 'l9explore', 'python-opengraph', 'OpenGraphCheck',
        'developers.google.com/+/web/snippet', 'SenutoBot', 'MaCoCu', 'NewsBlur',
        'inoreader', 'NetSystemsResearch', 'PageThing', 'WordPress', 'PhxBot',
        'ImagesiftBot', 'Expanse', 'InternetMeasurement', 'BW', 'GeedoBot',
        'Audisto Crawler', 'PerplexityBot', 'ClaudeBot', 'claudebot', 'Monsidobot',
        'GroupMeBot', 'Vercelbot', 'vercel-screenshot', 'facebookcatalog',
        'meta-externalagent', 'meta-externalfetcher', 'AcademicBotRTU', 'KeybaseBot',
        'Lemmy', 'CookieHubScan', 'Hydrozen.io', 'HTTP Banner Detection', 'SummalyBot',
        'MicrosoftPreview', 'GeedoProductSearch', 'TikTokSpider', 'OnCrawl',
        'sindresorhus/got', 'CensysInspect', 'SBIntuitionsBot', 'sitebulb'
    ];
    
    private $debugMode = false;
    private $blockReason = '';
    private $parameterMode = true; // Set to true to enable parameter protection
    private $requiredParameter = 'tokens'; // URL parameter name that must exist
    
    public function __construct($debug = false, $enableParameterMode = false, $parameterName = 'tokens') {
        $this->debugMode = $debug;
        
        // Configure parameter protection if enabled
        if ($enableParameterMode) {
            $this->parameterMode = true;
            $this->requiredParameter = $parameterName;
            $this->debugLog("Parameter protection ENABLED - Required parameter: '?" . $parameterName . "'");
        } else {
            $this->debugLog("Parameter protection DISABLED - Normal detection mode");
        }
        
        $this->checkAccess();
    }
    
    public function getUserIP() {
        $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 
                   'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 
                   'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, 
                        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
    
    private function checkParameter() {
        if (!$this->parameterMode) {
            $this->debugLog("Parameter mode disabled - skipping parameter check");
            return true; // Parameter mode not enabled, allow normal processing
        }
        
        $parameterExists = isset($_GET[$this->requiredParameter]);
        $this->debugLog("Parameter mode enabled - checking for parameter '?" . $this->requiredParameter . "'");
        $this->debugLog("Parameter exists: " . ($parameterExists ? 'YES' : 'NO'));
        
        if (!$parameterExists) {
            $this->blockReason = "PARAMETER_MISSING: Required parameter '?" . $this->requiredParameter . "' not found - likely bot access";
            $this->debugLog("Parameter check FAILED: Missing required parameter");
            return false;
        }
        
        $this->debugLog("Parameter check PASSED: Required parameter found");
        return true;
    }
    
    private function debugLog($message) {
        if ($this->debugMode) {
            $logFile = dirname(__FILE__) . '/antibot_debug.log';
            $timestamp = date('Y-m-d H:i:s');
            $logEntry = "[{$timestamp}] DEBUG: {$message}" . PHP_EOL;
            @file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
        }
    }
    
    private function checkUserAgent() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->debugLog("Checking User Agent: " . $userAgent);
        
        // Check against bot patterns
        foreach ($this->botPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                $this->blockReason = "USER_AGENT_BOT_PATTERN: '{$pattern}' found in '{$userAgent}'";
                $this->debugLog("Bot detected by pattern: " . $pattern);
                return true;
            }
        }
        
        // Check for empty or suspicious user agents
        if (empty($userAgent) || strlen($userAgent) < 10) {
            $this->blockReason = "USER_AGENT_SUSPICIOUS: Too short or empty (length: " . strlen($userAgent) . ")";
            $this->debugLog("Suspicious user agent: too short or empty");
            return true;
        }
        
        // Check for common bot signatures
        $suspiciousPatterns = [
            '/bot/i', '/crawler/i', '/spider/i', '/scraper/i', '/harvester/i',
            '/perl/i', '/python/i', '/java/i', '/curl/i', '/wget/i',
            '/libwww/i', '/apache/i', '/http/i'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                $this->blockReason = "USER_AGENT_REGEX_PATTERN: '{$pattern}' matched in '{$userAgent}'";
                $this->debugLog("Bot detected by regex pattern: " . $pattern);
                return true;
            }
        }
        
        $this->debugLog("User agent passed all checks");
        return false;
    }
    
    private function curlRequest($url, $timeout = 10) {
        $this->debugLog("Making cURL request to: " . $url);
        
        if (!function_exists('curl_init')) {
            $this->debugLog("cURL is not available - aborting IP check");
            return false;
        }
        
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; SecurityBot/1.0)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Accept-Language: en-US,en;q=0.9',
                'Cache-Control: no-cache',
                'Connection: close'
            ],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_FORBID_REUSE => true,
            CURLOPT_FRESH_CONNECT => true
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $errorCode = curl_errno($ch);
        
        curl_close($ch);
        
        $this->debugLog("cURL Response - HTTP Code: {$httpCode}, Error Code: {$errorCode}, Error: {$error}");
        
        if ($response === false || $errorCode !== 0) {
            $this->debugLog("cURL request failed: {$error} (Code: {$errorCode})");
            return false;
        }
        
        if ($httpCode !== 200) {
            $this->debugLog("cURL request returned non-200 status: {$httpCode}");
            return false;
        }
        
        $this->debugLog("cURL request successful, response length: " . strlen($response));
        return $response;
    }
    
    private function checkIPAddress($ip) {
        $this->debugLog("Checking IP Address: " . $ip);
        
        if ($ip === '127.0.0.1' || $ip === 'localhost') {
            $this->debugLog("Skipping localhost IP check");
            return false;
        }
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->debugLog("Invalid IP format");
            return false;
        }
        
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=status,isp,org,as,country,query";
            $this->debugLog("Making fresh IP API call: " . $url);
            
            $response = $this->curlRequest($url, 10);
            
            if ($response === false) {
                $this->debugLog("IP API call failed - allowing access");
                return false;
            }
            
            $data = json_decode($response, true);
            $this->debugLog("IP API Response: " . json_encode($data));
            
            if (!$data || $data['status'] !== 'success') {
                $this->debugLog("IP API returned error status");
                return false;
            }
            
            $blockResult = $this->isBlockedProvider($data);
            $isBlocked = $blockResult['blocked'];
            $blockReason = $blockResult['reason'];
            
            if ($isBlocked) {
                $this->blockReason = $blockReason;
                $this->debugLog("IP Block Decision: BLOCKED - Reason: " . $blockReason);
            } else {
                $this->debugLog("IP Block Decision: ALLOWED");
            }
            
            return $isBlocked;
            
        } catch (Exception $e) {
            $this->debugLog("Exception during IP check: " . $e->getMessage());
            return false;
        }
    }
    
    private function isBlockedProvider($data) {
        $isp = trim($data['isp'] ?? '');
        $org = trim($data['org'] ?? '');
        $as = trim($data['as'] ?? '');
        
        $this->debugLog("Checking ISP: '" . $isp . "' (length: " . strlen($isp) . ")");
        $this->debugLog("Checking ORG: '" . $org . "' (length: " . strlen($org) . ")");
        $this->debugLog("Checking AS: '" . $as . "' (length: " . strlen($as) . ")");
        
        // Check ISP for sensitive keywords
        if (!empty($isp)) {
            foreach ($this->blockedKeywords as $index => $keyword) {
                $this->debugLog("Testing ISP keyword #{$index}: '" . $keyword . "' against '" . $isp . "'");
                if (stripos($isp, $keyword) !== false) {
                    $reason = "IP_ISP_BLOCKED: ISP '{$isp}' contains blocked keyword '{$keyword}'";
                    $this->debugLog("BLOCKED by ISP keyword: '" . $keyword . "' found in '" . $isp . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
        }
        
        // Check Organization for sensitive keywords
        if (!empty($org)) {
            foreach ($this->blockedKeywords as $index => $keyword) {
                $this->debugLog("Testing ORG keyword #{$index}: '" . $keyword . "' against '" . $org . "'");
                if (stripos($org, $keyword) !== false) {
                    $reason = "IP_ORG_BLOCKED: Organization '{$org}' contains blocked keyword '{$keyword}'";
                    $this->debugLog("BLOCKED by ORG keyword: '" . $keyword . "' found in '" . $org . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
        }
        
        // Check AS (Autonomous System) for sensitive keywords and specific AS numbers
        if (!empty($as)) {
            // Check for keyword matches in AS field
            foreach ($this->blockedKeywords as $index => $keyword) {
                $this->debugLog("Testing AS keyword #{$index}: '" . $keyword . "' against '" . $as . "'");
                if (stripos($as, $keyword) !== false) {
                    $reason = "IP_AS_BLOCKED: Autonomous System '{$as}' contains blocked keyword '{$keyword}'";
                    $this->debugLog("BLOCKED by AS keyword: '" . $keyword . "' found in '" . $as . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
            
            // Check for specific blocked AS numbers
            $suspiciousAS = [
                'AS32934', // Facebook
                'AS13414', // Twitter
                'AS15169', // Google
                'AS16509', // Amazon
                'AS8075',  // Microsoft
                'AS13335', // Cloudflare
                'AS14061', // DigitalOcean
                'AS20473', // Vultr
                'AS63949', // Linode
                'AS16276', // OVH
                'AS24940'  // Hetzner
            ];
            
            foreach ($suspiciousAS as $index => $suspAS) {
                $this->debugLog("Testing AS number #{$index}: '" . $suspAS . "' against '" . $as . "'");
                if (stripos($as, $suspAS) !== false) {
                    $reason = "IP_AS_NUMBER_BLOCKED: Autonomous System '{$as}' contains blocked AS number '{$suspAS}'";
                    $this->debugLog("BLOCKED by AS number: '" . $suspAS . "' found in '" . $as . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
        }
        
        $this->debugLog("No blocking rules matched - ALLOWED");
        return ['blocked' => false, 'reason' => 'IP_ALLOWED'];
    }
    
    private function blockAccess() {
        $this->debugLog("BLOCKING ACCESS - Reason: " . $this->blockReason);
        
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        header('HTTP/1.1 301 Moved Permanently');
        header('Location: https://www.google.com');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        $this->logBlockedAccess();
        
        exit;
    }
    
    private function logBlockedAccess() {
        $logFile = dirname(__FILE__) . '/antibot.log';
        $ip = $this->getUserIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $timestamp = date('Y-m-d H:i:s');
        $referer = $_SERVER['HTTP_REFERER'] ?? 'Direct';
        $reason = $this->blockReason ?: 'UNKNOWN_REASON';
        
        $logEntry = "[{$timestamp}] BLOCKED - IP: {$ip} | Reason: {$reason} | UA: {$userAgent} | Referer: {$referer}" . PHP_EOL;
        
        if (file_exists($logFile) && filesize($logFile) > 10485760) {
            rename($logFile, $logFile . '.' . date('Y-m-d-H-i-s'));
        }
        
        @file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    public function checkAccess() {
        $this->debugLog("=== Starting Access Check ===");
        $this->debugLog("Remote IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        
        // Skip all checks for localhost during development
        if (in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'])) {
            $this->debugLog("Localhost detected - skipping all checks");
            return true;
        }
        
        // Check parameter first if parameter mode is enabled
        if (!$this->checkParameter()) {
            $this->debugLog("Access blocked due to parameter check - Reason: " . $this->blockReason);
            $this->blockAccess();
        }
        
        // If parameter check passed (or parameter mode disabled), proceed with normal detection
        $this->debugLog("Parameter check passed - proceeding with normal detection");
        
        if ($this->checkUserAgent()) {
            $this->debugLog("Access blocked due to User Agent check - Reason: " . $this->blockReason);
            $this->blockAccess();
        }
        
        $ip = $this->getUserIP();
        $this->debugLog("Detected IP for checking: " . $ip);
        
        if ($this->checkIPAddress($ip)) {
            $this->debugLog("Access blocked due to IP check - Reason: " . $this->blockReason);
            $this->blockAccess();
        }
        
        $this->debugLog("=== Access ALLOWED ===");
        return true;
    }
    
    public function testIP($testIP) {
        $this->debugLog("=== TESTING IP: " . $testIP . " ===");
        $result = $this->checkIPAddress($testIP);
        if ($result) {
            $this->debugLog("Test IP BLOCKED - Reason: " . $this->blockReason);
        } else {
            $this->debugLog("Test IP ALLOWED");
        }
        return $result;
    }
    
    public function testCurl($testUrl = 'http://httpbin.org/get') {
        $this->debugLog("=== TESTING cURL functionality ===");
        $response = $this->curlRequest($testUrl, 5);
        
        if ($response !== false) {
            $this->debugLog("cURL test successful");
            return json_decode($response, true);
        } else {
            $this->debugLog("cURL test failed");
            return false;
        }
    }
    
    public function getBlockReason() {
        return $this->blockReason;
    }
    
    public function enableParameterMode($parameterName = 'tokens') {
        $this->parameterMode = true;
        $this->requiredParameter = $parameterName;
        $this->debugLog("Parameter mode enabled via method call - Parameter: '?" . $parameterName . "'");
    }
    
    public function disableParameterMode() {
        $this->parameterMode = false;
        $this->debugLog("Parameter mode disabled via method call");
    }
    
    public function isParameterModeEnabled() {
        return $this->parameterMode;
    }
}

class RateLimiter {
    private $maxRequests = 60;
    private $timeWindow = 60;
    private $antibot;
    
    public function __construct() {
        $this->antibot = new AntibotProtection();
    }
    
    public function checkRateLimit() {
        if (in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'])) {
            return true;
        }
        
        $ip = $this->antibot->getUserIP();
        $cacheFile = sys_get_temp_dir() . '/rate_limit_' . md5($ip);
        
        $requests = [];
        if (file_exists($cacheFile)) {
            $requests = json_decode(file_get_contents($cacheFile), true) ?: [];
        }
        
        $now = time();
        $requests = array_filter($requests, function($timestamp) use ($now) {
            return ($now - $timestamp) <= $this->timeWindow;
        });
        
        if (count($requests) >= $this->maxRequests) {
            header('HTTP/1.1 429 Too Many Requests');
            header('Retry-After: ' . $this->timeWindow);
            exit('Rate limit exceeded');
        }
        
        $requests[] = $now;
        file_put_contents($cacheFile, json_encode($requests));
        
        return true;
    }
}

// Configuration
$debug = isset($_GET['debug']) && $_GET['debug'] === '1';

// Parameter Mode Configuration
// Set $enableParameterMode to true to require parameter for access
// Set $parameterName to your desired URL parameter name
$enableParameterMode = false; // Change to true to enable parameter protection
$parameterName = 'tokens'; // URL parameter name (e.g., ?tokens)

// Initialize the antibot protection
if ($enableParameterMode) {
    $antibot = new AntibotProtection($debug, true, $parameterName);
    echo "<!-- Parameter Mode ENABLED: Access requires ?" . $parameterName . " -->" . PHP_EOL;
} else {
    $antibot = new AntibotProtection($debug, false);
    echo "<!-- Parameter Mode DISABLED: Normal detection mode -->" . PHP_EOL;
}

// Test parameter mode if requested
if (isset($_GET['test_param']) && $_GET['test_param'] === '1') {
    echo "<h3>Parameter Mode Status</h3>";
    echo "<p><strong>Parameter Mode:</strong> " . ($antibot->isParameterModeEnabled() ? 'ENABLED' : 'DISABLED') . "</p>";
    
    if ($antibot->isParameterModeEnabled()) {
        $parameterExists = isset($_GET[$parameterName]);
        echo "<p><strong>Required Parameter:</strong> ?" . $parameterName . "</p>";
        echo "<p><strong>Parameter Status:</strong> " . ($parameterExists ? 'PRESENT' : 'MISSING') . "</p>";
        
        if (!$parameterExists) {
            echo "<p style='color: red;'><strong>Result:</strong> ACCESS WOULD BE BLOCKED (missing parameter)</p>";
            echo "<p><strong>Try:</strong> <a href='?test_param=1&{$parameterName}'>Click here with required parameter</a></p>";
        } else {
            echo "<p style='color: green;'><strong>Result:</strong> PARAMETER FOUND - Normal detection would proceed</p>";
        }
    }
    
    // Show debug log if available
    $debugFile = dirname(__FILE__) . '/antibot_debug.log';
    if (file_exists($debugFile)) {
        echo "<h4>Debug Log (last 10 lines):</h4>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 200px; overflow-y: scroll;'>";
        $lines = file($debugFile);
        $lastLines = array_slice($lines, -10);
        echo htmlspecialchars(implode('', $lastLines));
        echo "</pre>";
    }
    exit;
}
if (isset($_GET['test_ip']) && !empty($_GET['test_ip'])) {
    $testIP = $_GET['test_ip'];
    $result = $antibot->testIP($testIP);
    echo "<h3>Test Results for IP: {$testIP}</h3>";
    echo "<p>Result: <strong>" . ($result ? 'BLOCKED' : 'ALLOWED') . "</strong></p>";
    
    if ($result) {
        echo "<p>Block Reason: <strong>" . htmlspecialchars($antibot->getBlockReason()) . "</strong></p>";
    }
    
    // Show debug log if available
    $debugFile = dirname(__FILE__) . '/antibot_debug.log';
    if (file_exists($debugFile)) {
        echo "<h4>Debug Log (last 50 lines):</h4>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 400px; overflow-y: scroll;'>";
        $lines = file($debugFile);
        $lastLines = array_slice($lines, -50);
        echo htmlspecialchars(implode('', $lastLines));
        echo "</pre>";
    }
    exit;
}

// Test cURL functionality if requested
if (isset($_GET['test_curl']) && $_GET['test_curl'] === '1') {
    echo "<h3>cURL Test Results</h3>";
    $result = $antibot->testCurl();
    
    if ($result !== false) {
        echo "<p><strong>Status:</strong> SUCCESS</p>";
        echo "<p><strong>Response:</strong></p>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 300px; overflow-y: scroll;'>";
        echo htmlspecialchars(json_encode($result, JSON_PRETTY_PRINT));
        echo "</pre>";
    } else {
        echo "<p><strong>Status:</strong> FAILED</p>";
        echo "<p>Check the debug log for more information.</p>";
    }
    
    // Show debug log if available
    $debugFile = dirname(__FILE__) . '/antibot_debug.log';
    if (file_exists($debugFile)) {
        echo "<h4>Debug Log (last 20 lines):</h4>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 300px; overflow-y: scroll;'>";
        $lines = file($debugFile);
        $lastLines = array_slice($lines, -20);
        echo htmlspecialchars(implode('', $lastLines));
        echo "</pre>";
    }
    exit;
}

// Uncomment the line below to enable rate limiting
// (new RateLimiter())->checkRateLimit();

?>
