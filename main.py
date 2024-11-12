import asyncio
from assistants.browser_assistant import BrowserAssistant
from assistants.terminal_assistant import TerminalAssistant
from assistants.langchain_assistant import LangchainAssistant
from assistants.security_tools import SecurityTools
from assistants.attack_strategist import AttackStrategist
from assistants.offensive_assistant import OffensiveAssistant
from utils.results_logger import ResultsLogger
from assistants.orchestrator import Orchestrator

async def main():
    # Initialize all assistants
    browser = BrowserAssistant()
    terminal = TerminalAssistant()
    langchain = LangchainAssistant()
    security = SecurityTools()
    attack_strategist = AttackStrategist()
    offensive = OffensiveAssistant()
    logger = ResultsLogger()

    # Create orchestrator with all assistants
    orchestrator = Orchestrator({
        'browser': browser,
        'terminal': terminal,
        'langchain': langchain,
        'security': security,
        'attack_strategist': attack_strategist,
        'offensive': offensive
    })

    target_url = "https://veriftools.net/en/"

    try:
        print("\n=== Starting Orchestrated Security Assessment ===")
        await logger.start_new_scan(target_url)
        
        # Let orchestrator handle the entire process
        results = await orchestrator.orchestrate_scan(target_url)
        
        # Log final results
        await logger.log_phase_result("orchestrated_scan", results)
        print(f"\nScan Results saved to: {logger.get_results_path()}")

    except Exception as e:
        error_msg = f"Error during orchestrated assessment: {str(e)}"
        print(error_msg)
        await logger.log_error(error_msg)
    
    finally:
        # Cleanup
        await browser.close_browser()
        await security.close()
        await offensive.close()
        print(f"\n=== Security Assessment Complete ===")

if __name__ == "__main__":
    print("Starting ShadowScout AI...")
    asyncio.run(main())