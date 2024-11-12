import asyncio
from assistants.browser_assistant import BrowserAssistant
from assistants.terminal_assistant import TerminalAssistant
from assistants.langchain_assistant import LangchainAssistant
from assistants.security_tools import SecurityTools
from utils.results_logger import ResultsLogger

async def main():
    # Initialize Assistants and Logger
    browser = BrowserAssistant()
    terminal = TerminalAssistant()
    langchain = LangchainAssistant()
    security = SecurityTools()
    logger = ResultsLogger()

    target_url = "http://play.firekirin.in/web_mobile/firekirin_pc/"

    try:
        print("\n=== Starting Autonomous Security Assessment ===")
        await logger.start_new_scan(target_url)
        
        print(f"\nInitiating autonomous security check for: {target_url}")
        
        # Phase 1: Reconnaissance
        print("\nPhase 1: Initial Reconnaissance")
        recon_response = await langchain.process_text(
            f"Analyze {target_url} structure and identify potential security test points."
        )
        await logger.log_phase_result("reconnaissance", recon_response)
        print(f"Reconnaissance Results: {recon_response}")

        # Phase 2: Vulnerability Assessment
        print("\nPhase 2: Vulnerability Assessment")
        security_queries = [
            f"Scan {target_url} for common web vulnerabilities.",
            f"Check {target_url} for injection vulnerabilities.",
            f"Analyze the response headers and security configurations of {target_url}"
        ]

        for i, query in enumerate(security_queries, 1):
            print(f"\nExecuting: {query}")
            response = await langchain.process_text(query)
            await logger.log_phase_result(f"vulnerability_scan_{i}", response)
            print(f"Results: {response}")
            await asyncio.sleep(2)

        # Phase 3: Result Analysis
        print("\nPhase 3: Result Analysis")
        final_analysis = await langchain.process_text(
            f"Provide a comprehensive security analysis of {target_url} based on all previous scan results."
        )
        await logger.log_phase_result("final_analysis", final_analysis)
        print(f"Final Analysis: {final_analysis}")

    except Exception as e:
        error_msg = f"Error during security assessment: {str(e)}"
        print(error_msg)
        await logger.log_error(error_msg)
        
        try:
            print("\nAttempting alternative assessment approach...")
            recovery_response = await langchain.process_text(
                f"Previous security assessment of {target_url} failed. Try alternative methods."
            )
            await logger.log_phase_result("recovery_attempt", recovery_response)
            print(f"Recovery Results: {recovery_response}")
        except Exception as recovery_error:
            await logger.log_error(f"Recovery attempt failed: {str(recovery_error)}")
    
    finally:
        # Cleanup
        await browser.close_browser()
        await security.close()
        print(f"\n=== Security Assessment Complete ===")
        print(f"Results saved to: {logger.get_results_path()}")

if __name__ == "__main__":
    print("Starting Enhanced Security Assessment System...")
    asyncio.run(main())