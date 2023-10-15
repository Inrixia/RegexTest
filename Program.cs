using PCRE;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace RegexTest
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string[] testUrls = UrlGenerator.GenerateTestUrls(1000);
            //Console.WriteLine(string.Join("\n", testUrls));
            //Console.WriteLine("\n\n");
            //Console.WriteLine(string.Join("\n", RegexRulesets.stateMachineSupported));
            //Console.WriteLine("\n\n");
            //Console.WriteLine(string.Join("\n", RegexRulesets.stateMachineNotSupported));
            //Console.WriteLine("\n\n\n");

            // Assuming that the 'stateMachineSupported' contains an array of regex patterns
            CheckUrlMatches(testUrls, RegexRulesets.re2Supported, "Re2 Supported", true);

            Console.WriteLine("\n\n\n");
            // Assuming that the 'stateMachineNotSupported' contains an array of regex patterns
            CheckUrlMatches(testUrls, RegexRulesets.allTypes, "Re2 Not Supported", false);

            Console.ReadKey();
        }

        private static double StopMs(Stopwatch stopwatch)
        {
            // Ensure the stopwatch is stopped before getting the elapsed time
            stopwatch.Stop();

            // ElapsedTicks: Gets the total elapsed time measured by the current instance, in timer ticks.
            // Stopwatch.Frequency: Gets the frequency of the timer as the number of ticks per second. 
            // This will convert the elapsed ticks to milliseconds with high precision.
            return 1000.0 * stopwatch.ElapsedTicks / Stopwatch.Frequency;
        }

        private static readonly List<string> errors = new List<string>();
        private static double TestEngine(string[] testUrls, Func<string, bool> isMatch, string name, string rule)
        {
            try
            {
                Stopwatch stopwatch = new Stopwatch();
                double totalMilliseconds = 0;
                foreach (string url in testUrls)
                {
                    stopwatch.Restart();
                    isMatch(url);
                    isMatch(url);
                    stopwatch.Stop();
                    double runTime = StopMs(stopwatch);

                    if (totalMilliseconds > MaxTestTime)
                    {
                        errors.Add($"TIMEOUOT: {name} took [{runTime}/{totalMilliseconds}]ms!");
                        return -1;
                    }

                    totalMilliseconds += runTime;
                }
                return totalMilliseconds;
            }
            catch (RegexMatchTimeoutException)
            {
                errors.Add($"TIMEOUT: {name}");
                return -1;
            }
            catch (Exception ex)
            {
                errors.Add($"{ex.GetType().Name}: {name} \"{rule}\" failed: {ex.Message}");
                return -1;
            }
        }

        private const double MaxTestTime = 10000;

        private static void CheckUrlMatches(string[] testUrls, (string Comment, string[] Rules)[] regexRuleSets, string ruleSetName, bool re2Support)
        {
            Console.WriteLine($"---- Checking {ruleSetName} Rules ----");
            Console.WriteLine($"{"Regex Rule",-32} => {"PcreZA, ",12}{"PcreDFA, ",16}{"Pcre, ",16}{"Re2, ",18}{".Net, ",16}");

            foreach (var (comment, rules) in regexRuleSets)
            {
                int r = 0;
                foreach (string regexRule in rules)
                {
                    var dotNet = new Regex(regexRule, RegexOptions.Compiled, TimeSpan.FromMilliseconds(500));
                    var pcre = new PcreRegex(regexRule, new PcreRegexSettings() { Options = PcreOptions.Compiled });
                    var pcreZA = pcre.CreateMatchBuffer();
                    bool pcreZAIsMatch(string str) => pcreZA.IsMatch(new ReadOnlySpan<char>(str.ToCharArray()));
                    bool pcreDFAIsMatch(string str) => pcre.Dfa.Match(str, new PCRE.Dfa.PcreDfaMatchSettings() { WorkspaceSize = 1024 }).Success;

                    Console.Write($"{comment + '-' + r++,-32} => ");

                    double pcreZAt = TestEngine(testUrls, pcreZAIsMatch, "pcreZA", regexRule);
                    Console.Write($"{pcreZAt,8:F3}ms 1x, ");

                    double pcreDFAt = TestEngine(testUrls, pcreDFAIsMatch, "pcreDFA", regexRule);
                    Console.Write($"{pcreDFAt,8:F3}ms {pcreZAt / pcreDFAt,2:F2}x, ");

                    double pcret = TestEngine(testUrls, pcre.IsMatch, "pcre", regexRule);
                    Console.Write($"{pcret,8:F3}ms {pcreZAt / pcret,2:F2}x, ");

                    if (re2Support)
                    {
                        var re2 = new Re2.Net.Regex(regexRule);
                        double re2t = TestEngine(testUrls, re2.IsMatch, "re2", regexRule);
                        Console.Write($"{re2t,8:F3}ms {pcreZAt / re2t,2:F2}x, ");
                    }
                    else
                    {
                        Console.Write($"{null,8:F3}ms 0x, ");
                    }

                    double dotNett = TestEngine(testUrls, dotNet.IsMatch, ".Net", regexRule);
                    Console.WriteLine($"{dotNett,8:F3}ms {pcreZAt / dotNett,2:F2}x");
                }
            }

            foreach (string err in errors) Console.WriteLine(err);
        }
    }

    public class UrlGenerator
    {
        private static readonly Random rnd = new Random();

        public static string[] GenerateTestUrls(int count)
        {
            var urls = new List<string>();

            for (int i = 0; i < count; i++)
            {
                // Dynamic URL Pattern
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/{RndStr()}/{RndStr()}/{RndStr()}{RndQStr()}");
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/{RndStr()}/{RndStr()}/{RndStr()}");
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/{RndStr()}");

                // Simple SharePoint URL
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}");

                // URL with GUID
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/{Guid.NewGuid()}");

                // API Calls
                string[] oDataQueries = new string[]
                {
                    $"$filter={RndStr()}",
                    $"$select={RndStr()}",
                    $"$orderby={RndStr()}",
                    $"$top={rnd.Next(1, 100)}",
                    $"$skip={rnd.Next(1, 100)}",
                    $"$expand={RndStr()}",
                    "$count=true"
                };
                foreach (string api in ApiCalls)
                {
                    urls.Add($"https://{RndDnsName()}/{RndStr()}/{api}");
                    urls.Add($"https://{RndDnsName()}/{RndStr()}/{api}{RndQStr()}");
                    foreach (string query in oDataQueries)
                    {
                        urls.Add($"https://{RndDnsName()}/{RndStr()}/{api}{query}");
                    }
                }
                urls.Add($"https://{RndDnsName()}/_api/web/lists/getbytitle('{RndStr()}')/items");
                urls.Add($"https://{RndDnsName()}/_api/web/lists/getbytitle('{RndStr()}')/items?{string.Join("&", oDataQueries)}");


                // Asset URL
                foreach (string asset in AssetTypes)
                {
                    urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/Style%20Library/{RndStr()}.{asset}");
                    urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/Style%20Library/{RndStr()}.{asset}{RndQStr()}");
                }

                // Document URL with Version
                urls.Add($"https://{RndDnsName()}/_layouts/15/WopiFrame.aspx/sourcedoc={RndStr()}&action=view");

                // People or Group Profile URL
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/_layouts/15/userdisp.aspx?ID={rnd.Next(1, 100)}");

                // Complex URL with Query Strings
                urls.Add($"https://{RndDnsName()}/sites/{RndStr()}/{RndStr()}.aspx{RndQStr()}");
            }

            return urls.ToArray();
        }

        private static readonly char[] chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~$!+%".ToCharArray();

        private static string RndStr()
        {
            int length = rnd.Next(5, 15);
            char[] stringChars = new char[length];

            for (int i = 0; i < length; i++) stringChars[i] = chars[rnd.Next(chars.Length)];

            return WebUtility.UrlEncode(new string(stringChars));
        }

        private static readonly string[] TLDs =
        {
            "com", "net", "org", "io", "dev", "gov", "edu", "mil", "int",
            "eu", "us", "uk", "de", "ca", "fr", "au", "br", "cn", "ru", "jp",
        };
        private const string dnsChars = "abcdefghijklmnopqrstuvwxyz0123456789-";
        private static string RndDnsStr(int minLength = 2, int maxLength = 8)
        {
            int length = rnd.Next(minLength, maxLength + 1);
            char[] domainChars = new char[length];

            // Ensuring the first character is not a hyphen.
            domainChars[0] = dnsChars[rnd.Next(dnsChars.Length - 1)]; // Exclude hyphen for the first char

            // Ensuring the last character is not a hyphen.
            domainChars[length - 1] = dnsChars[rnd.Next(dnsChars.Length - 1)]; // Exclude hyphen for the last char

            for (int i = 1; i < length - 1; i++)
            {
                domainChars[i] = dnsChars[rnd.Next(dnsChars.Length)]; // Include hyphen for the middle chars
            }

            return new string(domainChars);
        }

        public static string RndDnsName()
        {
            int subdomainCount = rnd.Next(0, 6); // Generate 0 to 5 subdomains
            StringBuilder domainName = new StringBuilder();

            for (int i = 0; i < subdomainCount; i++)
                domainName.Append($"{RndDnsStr()}.");

            // Append main domain and top-level domain
            domainName.Append($"{RndDnsStr()}.{TLDs[rnd.Next(TLDs.Length)]}");

            return domainName.ToString();
        }

        private static string RndQStr()
        {
            int paramCount = rnd.Next(1, 5);
            StringBuilder sb = new StringBuilder("?");
            for (int i = 0; i < paramCount; i++)
            {
                string key = RndStr();
                string value = RndStr();
                if (i > 0) sb.Append("&");
                sb.Append($"{key}={value}");
            }
            return sb.ToString();
        }

        public static readonly string[] ApiCalls = new[]
        {
            "_api/web/lists",
            "_api/web/webs",
            "_api/contextinfo",
            "_api/search/query",
            "_api/web/siteusers",
            "_api/web/fields",
            "_api/web/contenttypes",
            "_api/search/suggest",
            "_api/web/features",
            "_api/web/navigation/nodes",
            "_api/web/folders",
            "_api/web/roleassignments",
            "_api/web/sitegroups",
            "_api/web/usercustomactions",
            "_api/web/webinfos",
            "_api/web/workflowassociations",
            "_api/SP.UserProfiles.PeopleManager/GetMyProperties",
            "_api/social.feed/my/mentions",
            "_api/social.feed/my/news",
            "_api/social.feed/my/timelinefeed",
            "_api/social.following/my/followed(types=15)",
            "_api/social.following/my/followers",
            "_api/search/postquery",
            "_api/web/lists/getbytitle"
        };

        public static readonly string[] AssetTypes = new[]
        {
            "png",
            "jpg",
            "jpeg",
            "gif",
            "bmp",
            "tif",
            "tiff",
            "svg",
            "webp",
            "ico",
            "css",
            "js",
            "woff",
            "woff2",
            "ttf",
            "eot",
            "otf",
            "mp4",
            "webm",
            "ogv",
            "mp3",
            "ogg",
            "wav",
            "flac",
            "aac",
            "m4a",
            "pdf",
            "doc",
            "docx",
            "ppt",
            "pptx",
            "xls",
            "xlsx",
            "zip",
            "rar",
            "tar",
            "gz",
            "7z",
            "bz2",
            "jar",
            "swf",
            "xml",
            "json",
            "txt",
            "rtf",
            "csv",
            "md",
            "html",
            "htm",
            "php",
            "asp",
            "aspx",
            "jsp",
            "py",
            "rb",
            "java",
            "pl",
            "mjs",
            "cjs"
        };
    }

    internal static class RegexRulesets
    {
        public static readonly (string Comment, string[] Rules)[] re2Supported = new[]
        {
            ("Dynamic URL Pattern", new[]
            {
                @"https://[\w.-]+/sites/[\w%\-~!$+]+/[\w%\-~!$+]*/[\w%\-~!$+]*/[\w%\-~!$+]*"
            }),
            ("Simple SharePoint URL", new[]
            {
                @"https://[\w.-]+/sites/[\w%\-~!$+]+"
            }),
            ("URL with GUID", new[]
            {
                @"https://[\w.-]+/sites/[\w%\-~!$+]+/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
            }),
            ("API Calls", new[]
            {
                $@"https://[\w.-]+/[\w%\-~!$+/]+/({string.Join("|", UrlGenerator.ApiCalls.Select(System.Text.RegularExpressions.Regex.Escape))})"
            }),
            ("Asset URL", new[]
            {
                @"https://[\w.-]+/sites/[\w%\-~!$+]+/Style%20Library/[\w%\-~!$+]+\.(png|jpg|jpeg|gif)",
                $@"https://[\w.-]+/sites/[\w%\-~!$+/]+/Style%20Library/[\w%\-~!$+.]+\.(?i:({string.Join("|", UrlGenerator.AssetTypes.Select(System.Text.RegularExpressions.Regex.Escape))}))"
            }),
            ("Document URL with Version", new[]
            {
                @"https://[\w.-]+/_layouts/15/WopiFrame\.aspx/sourcedoc=[\w%\-~!$+]+&action=view"
            }),
            ("People or Group Profile URL", new[]
            {
                @"https://[\w.-]+/sites/[\w%\-~!$+]+/_layouts/15/userdisp\.aspx\?ID=[0-9]{1,3}"
            }),
            ("Complex URL with Query Strings", new[]
            {
                @"https://[\w.-]+/sites/[\w%\-~!$+]+/[\w%\-~!$+]+\.aspx\?[\w%\-~!$+]+=[\w%\-~!$+]+"
            }),
            ("Generic", new[]
            {
                @"^https?:\/\/[\w\d-]+(\.[a-z]{2,})+\/?\S*$",
                @"^https?:\/\/(?:[a-z0-9]+(?:-?[a-z0-9]+)*\.)+[a-z]{2,}(?:\/\S*)?$",
                @"^https?:\/\/[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*(\.[a-zA-Z]{2,3})+(\/\w+)*$",
                @"^https?:\/\/[a-zA-Z0-9-]+(\.[a-zA-Z0-9]{2,})+(\/\S*)?$",
                @"^https?:\/\/[\w.-]+(?:\.[a-z]{2,})+(:\d{2,5})?\/?\S*$",
                @"^https?:\/\/[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+\/?[^\s]*$",
                @"^https?:\/\/[a-zA-Z0-9]+(?:\.[a-zA-Z]{2,})+(:\d{2,5})?\/?[^\s]*$",
                @"^https?:\/\/(?:[a-zA-Z0-9]+-?)*[a-zA-Z0-9]+(?:\.[a-z]{2,})+(?:\/[^\s]*)?$",
                @"^https?:\/\/[a-zA-Z0-9._%+-]+:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:\/\S*)?$",
                @"^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:\/[^\s]*)?$"
            }),
            ("Diverse", new[]
            {
                @"^http(s)?://([\w-]+\.)+[\w-]+(/[-\w ;,./?%&=]*)?$",
                @"^.{3,10}$",
                @"hello",
                @"^[^\W\d_](\w|'|-|\.)*$",
                @"(foo|bar|baz)",
                @"^\b\w+\b$",
                @"[[:alpha:]]{5}",
                @"(https?:\/\/[^\s]+)",
                @"^(?:http|https)://[^\s]+$",
                @"^[a-zA-Z]+$"
            }),
            ("Stress Test", new[]
            {
                @"(a+)+",
                @"([a-zA-Z]+)*",
                @"(\w+\d+)+",
                @"[\d\W\s]+",
                @"(?:a{1,6}){2,}",
                @"[^\W_]{10,50}",
                @"(?:[a-z]{2,4}){5,}",
                @"(123|124|125|126)+",
                @"(a|b|c|d|e|f|g|h|1|2|3|4)+",
                @"(https?|ftp)://[^\s/$.?#].[^\s]*",
                @"(a+|b+|c+){5,}",
                @"(?:\d{2,4}\.){2,}[\w-]+",
                @"(\w+|\d+|[^a-z]+){3,}",
                @"[\w-]+@[a-z]+(?:\.[a-z]{2,})+",
                @"(?:\w+\b){4,}",
                @"[^foo][^bar][^baz].+",
                @"[\w.-]+(?:\.[a-z]{2,}){1,2}",
                @"(?:[a-z]{3,}\d{2,}){5,}",
                @"(https?|ftp)://[^\s/$.?#].[^\s]*",
                @"(?:.*[a-z].*){3,}(?:.*[A-Z].*){2,}(?:.*\d.*){2,}[a-zA-Z\d]{8,}"
            })
        };

        public static readonly (string Comment, string[] Rules)[] allTypes = new[]
        {
            ("Dynamic URL Pattern", new[]
            {
                 @"https://(?<domain>[\w.-]+)/sites/(?<path>[\w%\-~!$+/]+)"
            }),
            ("Simple SharePoint URL", new[]
            {
                @"https://(?<domain>[\w.-]+)/sites/(?<siteName>[\w%\-~!$+]+)"
            }),
            ("URL with GUID", new[]
            {
                @"https://(?<domain>[\w.-]+)/sites/(?<siteName>[\w%\-~!$+]+)/(?<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})"
            }),
            ("API Calls", new[]
            {
                @"https://(?<domain>[\w.-]+)/(?<apiPath>[\w%\-~!$+/]+)/(?<apiCall>_api/.+?)\??(?<params>\$[a-z]+=[\w%\-~!$+]*)?",
                $@"https://(?<domain>[\w.-]+)/(?<apiPath>[\w%\-~!$+/]+)/(?<apiCall>({string.Join("|", UrlGenerator.ApiCalls.Select(System.Text.RegularExpressions.Regex.Escape))}))\??(?<params>\$[a-z]+=[\w%\-~!$+]*)?"
            }),
            ("Asset URL", new[]
            {
                $@"https://(?<domain>[\w.-]+)/sites/(?<siteName>[\w%\-~!$+]+)/Style%20Library/(?<fileName>[\w%\-~!$+]+)\.(?<fileExt>{string.Join("|", UrlGenerator.AssetTypes.Select(System.Text.RegularExpressions.Regex.Escape))})"
            }),
            ("Document URL with Version", new[]
            {
                @"https://(?<domain>[\w.-]+)/_layouts/15/WopiFrame\.aspx/sourcedoc=(?<docId>[\w%\-~!$+]+)&action=view"
            }),
            ("People or Group Profile URL", new[]
            {
                @"https://(?<domain>[\w.-]+)/sites/(?<siteName>[\w%\-~!$+]+)/_layouts/15/userdisp\.aspx\?ID=(?<userId>[0-9]{1,3})"
            }),
            ("Complex URL with Query Strings", new[]
            {
                @"https://(?<domain>[\w.-]+)/sites/(?<siteName>[\w%\-~!$+]+)/(?<pageName>[\w%\-~!$+]+)\.aspx\?(?<params>[\w%\-~!$+]+=[\w%\-~!$+]+)"
            }),
            ("Generic Patterns", new[]
            {
                @"^https?:\/\/(?:www\.)?[\w\d-]+(\.[a-z]{2,})+\/?\S*$",
                @"^(https?:\/\/)?(www\.)?([a-zA-Z0-9_-]+)(\.[a-z]+)+(:\d{2,5})?\/(\w+\/?)*(\.\w{2,4})?$",
                @"https?:\/\/(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+?[a-z][a-z0-9-]*[a-z0-9]\/?)?(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'"".,<>?«»“”‘’])?",
                @"^https?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$",
                @"^(https?:\/\/)?([a-z\d][-a-z\d]*[a-z\d]\.)+[a-z][-a-z\d]*[a-z\d](?::\d+)?(?:\/[^?#]*)?(?:\?[^#]*)?(?:#.*)?$",
                @"^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$",
                @"^((ftp|http|https):\/\/)?(www\.)?(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?\/?[^\s]*$",
                @"^https?:\/\/(www\.)?[a-zA-Z0-9@:%._\\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)$",
                @"^https?:\/\/(\S+\:\S+@)?(www\.)?[a-zA-Z0-9-._]+(\.[a-zA-Z]{2,})(:[0-9]{2,5})?(\S*)?$",
                @"^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w\.-]*)*\/?$"
            }),
            ("Diverse", new[]
            {
                @"^http(s)?://([\w-]+\.)+[\w-]+(/[-\w ;,./?%&=]*)?$",
                @"^.{3,10}$",
                @"(?i)hello",
                @"^[^\W\d_](\w|'|-|\.)*$",
                @"(?<=@)\w+",
                @"(foo|bar|baz)",
                @"^\b\w+\b$",
                @"[[:alpha:]]{5}",
                @"(https?:\/\/[^\s]+)",
                @"(\w+)\s\(\1\)"
            }),
            ("Stress Test", new[]
            {
                @"(a+)+",
                @"([a-zA-Z]+)*",
                @"(x+x+)+y",
                @"(\w+\d+)+",
                @"(?i)(\W+|[.*+\-?^=!:${}()|\[\]\/\\])+",
                @"^(?=.*a)(?=.*b)(?=.*c)(?=.*d)(?=.*e)(?=.*f).+$",
                @"(\d{1,9}(,-)*){300}",
                @"(a|aa)+",
                @"[\d\W\s]+",
                @"(?:a{1,6}){2,}",
                @"(a+|b+|c+){5,}",
                @"(?:(\d{2,4})+\.){2,}[\w-]+",
                @"(\w+?|\d+?|[^a-z]+){3,}",
                @"^(?i)(?:\d{2,4}\.)?[a-z](?=[a-z]{3})",
                @"^(?!\d{2,})(\w+\b){4,}",
                @"^(?!.*(?:foo|bar|baz)).+$",
                @"(?<=@)[\w.-]+(\.(?:[a-z]{2,})){1,2}",
                @"(?:[a-z]{3,}\d{2,}){5,}",
                @"(a{2,})+\1{2,}",  // Involving backreference
                @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$", // Password validation
            })
        };
    }
}
