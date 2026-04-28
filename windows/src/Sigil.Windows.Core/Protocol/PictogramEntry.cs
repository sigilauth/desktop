namespace Sigil.Windows.Core.Protocol;

/// <summary>
/// Single emoji+word entry from the SIGIL-CONV-V1 session pictogram pool.
/// Per api/pictogram-pool-v1.json (192 entries, indices 0-191).
/// </summary>
public sealed record PictogramEntry(
    int Index,
    string Emoji,
    string Name);

/// <summary>
/// Session pictogram pool (192 entries).
/// Canonical pool defined in api/pictogram-pool-v1.json (commit fc24026).
/// </summary>
public static class PictogramPool
{
    private static readonly PictogramEntry[] Pool = InitializePool();

    /// <summary>
    /// Gets the pictogram entry at the specified index.
    /// </summary>
    /// <param name="index">Index in range [0, 191]</param>
    /// <returns>Emoji+word pair</returns>
    public static PictogramEntry GetEntry(int index)
    {
        if (index < 0 || index >= 192)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Index must be in range [0, 191]");
        }

        return Pool[index];
    }

    /// <summary>
    /// Gets pictogram entries for the given indices.
    /// </summary>
    public static PictogramEntry[] GetEntries(int[] indices)
    {
        return indices.Select(GetEntry).ToArray();
    }

    /// <summary>
    /// Returns speakable representation (space-separated names).
    /// Example: "apple rocket fox anchor moon house"
    /// </summary>
    public static string ToSpeakable(PictogramEntry[] entries)
    {
        return string.Join(" ", entries.Select(e => e.Name));
    }

    private static PictogramEntry[] InitializePool()
    {
        return new PictogramEntry[]
        {
            new(0, "🍎", "apple"),
            new(1, "🍌", "banana"),
            new(2, "🍇", "grapes"),
            new(3, "🍊", "orange"),
            new(4, "🍋", "lemon"),
            new(5, "🍒", "cherry"),
            new(6, "🍓", "strawberry"),
            new(7, "🥝", "kiwi"),
            new(8, "🍑", "peach"),
            new(9, "🍉", "melon"),
            new(10, "🍍", "pineapple"),
            new(11, "🍐", "pear"),
            new(12, "🥥", "coconut"),
            new(13, "🍈", "honeydew"),
            new(14, "🥕", "carrot"),
            new(15, "🌽", "corn"),
            new(16, "🥦", "broccoli"),
            new(17, "🍄", "mushroom"),
            new(18, "🌶️", "pepper"),
            new(19, "🥑", "avocado"),
            new(20, "🍅", "tomato"),
            new(21, "🥜", "peanut"),
            new(22, "🥒", "cucumber"),
            new(23, "🥔", "potato"),
            new(24, "🍆", "eggplant"),
            new(25, "🥗", "salad"),
            new(26, "🌰", "chestnut"),
            new(27, "🍠", "yam"),
            new(28, "🌾", "grain"),
            new(29, "🌿", "herb"),
            new(30, "🥖", "baguette"),
            new(31, "🍳", "egg"),
            new(32, "🍕", "pizza"),
            new(33, "🍔", "burger"),
            new(34, "🌮", "taco"),
            new(35, "🍩", "donut"),
            new(36, "🍪", "cookie"),
            new(37, "🍰", "cake"),
            new(38, "🍞", "bread"),
            new(39, "🍿", "popcorn"),
            new(40, "🍦", "icecream"),
            new(41, "🍫", "chocolate"),
            new(42, "🍬", "candy"),
            new(43, "🥐", "croissant"),
            new(44, "🥨", "pretzel"),
            new(45, "🥞", "pancake"),
            new(46, "🧀", "cheese"),
            new(47, "🥓", "bacon"),
            new(48, "☕", "coffee"),
            new(49, "🍵", "tea"),
            new(50, "🥤", "soda"),
            new(51, "🍼", "bottle"),
            new(52, "🍶", "sake"),
            new(53, "🍺", "beer"),
            new(54, "🍷", "wine"),
            new(55, "🥛", "milk"),
            new(56, "🍻", "beers"),
            new(57, "🥂", "toast"),
            new(58, "🥃", "whiskey"),
            new(59, "🍹", "tropical"),
            new(60, "🍸", "martini"),
            new(61, "🍾", "champagne"),
            new(62, "🚗", "car"),
            new(63, "🚕", "taxi"),
            new(64, "🚌", "bus"),
            new(65, "🚀", "rocket"),
            new(66, "✈️", "plane"),
            new(67, "🚁", "helicopter"),
            new(68, "⛵", "sailboat"),
            new(69, "🚲", "bicycle"),
            new(70, "🚂", "train"),
            new(71, "🚊", "tram"),
            new(72, "🚇", "subway"),
            new(73, "🚑", "ambulance"),
            new(74, "🚒", "firetruck"),
            new(75, "🚓", "police"),
            new(76, "🛵", "scooter"),
            new(77, "⛴️", "ferry"),
            new(78, "🐕", "dog"),
            new(79, "🐱", "cat"),
            new(80, "🐭", "mouse"),
            new(81, "🐰", "rabbit"),
            new(82, "🦊", "fox"),
            new(83, "🐻", "bear"),
            new(84, "🐼", "panda"),
            new(85, "🐨", "koala"),
            new(86, "🐯", "tiger"),
            new(87, "🦁", "lion"),
            new(88, "🐮", "cow"),
            new(89, "🐷", "pig"),
            new(90, "🐸", "frog"),
            new(91, "🐵", "monkey"),
            new(92, "🐘", "elephant"),
            new(93, "🦒", "giraffe"),
            new(94, "🐦", "bird"),
            new(95, "🦅", "eagle"),
            new(96, "🦆", "duck"),
            new(97, "🦉", "owl"),
            new(98, "🐧", "penguin"),
            new(99, "🐔", "chicken"),
            new(100, "🦜", "parrot"),
            new(101, "🐓", "rooster"),
            new(102, "🦃", "turkey"),
            new(103, "🐟", "fish"),
            new(104, "🐠", "reef"),
            new(105, "🐡", "blowfish"),
            new(106, "🦈", "shark"),
            new(107, "🐙", "octopus"),
            new(108, "🐚", "shell"),
            new(109, "🦀", "crab"),
            new(110, "🐢", "turtle"),
            new(111, "🐍", "snake"),
            new(112, "🌳", "tree"),
            new(113, "🌲", "pine"),
            new(114, "🌴", "palm"),
            new(115, "🌵", "cactus"),
            new(116, "🍀", "clover"),
            new(117, "🌸", "blossom"),
            new(118, "🌺", "hibiscus"),
            new(119, "🌻", "sunflower"),
            new(120, "🌷", "tulip"),
            new(121, "🌹", "rose"),
            new(122, "🍁", "maple"),
            new(123, "🍂", "leaf"),
            new(124, "🦋", "butterfly"),
            new(125, "🐝", "bee"),
            new(126, "🐞", "ladybug"),
            new(127, "🌈", "rainbow"),
            new(128, "⭐", "star"),
            new(129, "🌙", "moon"),
            new(130, "☀️", "sun"),
            new(131, "🌤️", "sunny"),
            new(132, "⛅", "cloudy"),
            new(133, "☁️", "cloud"),
            new(134, "🌧️", "rainy"),
            new(135, "⛈️", "storm"),
            new(136, "🌩️", "lightning"),
            new(137, "❄️", "snow"),
            new(138, "☃️", "snowman"),
            new(139, "🌬️", "wind"),
            new(140, "🌪️", "tornado"),
            new(141, "🌫️", "fog"),
            new(142, "💧", "droplet"),
            new(143, "⚡", "bolt"),
            new(144, "🏠", "house"),
            new(145, "🏡", "home"),
            new(146, "🏰", "castle"),
            new(147, "🏛️", "temple"),
            new(148, "🗼", "tower"),
            new(149, "🗿", "moai"),
            new(150, "⛺", "tent"),
            new(151, "⛰️", "mountain"),
            new(152, "🏔️", "peak"),
            new(153, "🌋", "volcano"),
            new(154, "🏝️", "island"),
            new(155, "🏖️", "beach"),
            new(156, "🏜️", "desert"),
            new(157, "🏕️", "camping"),
            new(158, "🌁", "foggy"),
            new(159, "🌉", "bridge"),
            new(160, "🔑", "key"),
            new(161, "🔔", "bell"),
            new(162, "📚", "books"),
            new(163, "⚓", "anchor"),
            new(164, "👑", "crown"),
            new(165, "💎", "diamond"),
            new(166, "🔥", "fire"),
            new(167, "🎁", "gift"),
            new(168, "🎈", "balloon"),
            new(169, "🎀", "ribbon"),
            new(170, "🔨", "hammer"),
            new(171, "🔧", "wrench"),
            new(172, "🎯", "target"),
            new(173, "🎲", "dice"),
            new(174, "🎨", "palette"),
            new(175, "🎪", "circus"),
            new(176, "🎸", "guitar"),
            new(177, "🎹", "piano"),
            new(178, "🎺", "trumpet"),
            new(179, "🎷", "sax"),
            new(180, "🥁", "drum"),
            new(181, "🎻", "violin"),
            new(182, "⚽", "soccer"),
            new(183, "🏀", "basketball"),
            new(184, "🏈", "football"),
            new(185, "⚾", "baseball"),
            new(186, "🎾", "tennis"),
            new(187, "🏐", "volleyball"),
            new(188, "🏉", "rugby"),
            new(189, "🏓", "pingpong"),
            new(190, "🏸", "badminton"),
            new(191, "⛳", "golf")
        };
    }
}
