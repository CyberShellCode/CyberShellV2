from cybershell.orchestrator import CyberShell
from cybershell.config import SafetyConfig

# Compatibility helpers (older vs newer orchestrator)
def make_bot():
    try:
        # Newer signature (planner_name/scorer_name/doc_root supported)
        return CyberShell(
            SafetyConfig(allow_private_ranges=True, allow_localhost=True),
            doc_root='docs',
            planner_name='depth_first',
            scorer_name='weighted_signal'
        )
    except TypeError:
        # Older signature — construct then configure attributes if present
        bot = CyberShell(SafetyConfig(allow_private_ranges=True, allow_localhost=True))
        try:
            from cybershell.planner import Planner
            bot.planner = Planner.from_name('depth_first')
        except Exception:
            pass
        try:
            from cybershell.scoring import SCORER_REGISTRY, DefaultScorer
            scorer = SCORER_REGISTRY.get('weighted_signal', DefaultScorer)()
            if hasattr(bot, 'scorer'):
                bot.scorer = scorer
            if hasattr(bot, 'ods') and hasattr(bot.ods, 'scorer'):
                bot.ods.scorer = scorer
        except Exception:
            pass
        try:
            # Set doc root if attribute exists
            if hasattr(bot, 'doc_root'):
                bot.doc_root = 'docs'
        except Exception:
            pass
        return bot

if __name__ == "__main__":
    bot = make_bot()
    try:
        print(bot.core_philosophies())
    except Exception:
        pass
    out = bot.execute('http://localhost:8000')
    print(out['report'])
