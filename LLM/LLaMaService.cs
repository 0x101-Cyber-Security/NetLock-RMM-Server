using LLama.Common;
using LLama;
using System.Text;
using NetLock_RMM_Server;

namespace NetLock_RMM_Server.LLM
{
    public class LLaMaService
    {
        private readonly InteractiveExecutor _executor;
        private readonly ChatSession _session;

        public LLaMaService()
        {
            try
            {
                string modelPath = Application_Paths.llm_model_path;
                var parameters = new ModelParams(modelPath)
                {
                    ContextSize = 2048, // The longest length of chat as memory.
                    GpuLayerCount = 0, // For CPU, set this to 0
                   
                };

                var model = LLamaWeights.LoadFromFile(parameters);
                var context = model.CreateContext(parameters);
                _executor = new InteractiveExecutor(context);

                var chatHistory = new ChatHistory();
                //chatHistory.AddMessage(AuthorRole.System, "Your role is to write, fix and optimize code for the user requesting. Nothing else.");

                _session = new ChatSession(_executor, chatHistory);
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.LLM.LLaMaService.LLaMaService", "", ex.ToString());
            }
        }

        public async Task<string> GetResponseAsync(string userInput)
        {
            try
            {
                var inferenceParams = new InferenceParams
                {
                    MaxTokens = 512, // Allow longer responses if needed
                    AntiPrompts = new List<string> { "---" }, // Use multiple stop triggers for clarity
                    Temperature = 0.5f, // Lower temperature for more deterministic responses
                    TopP = 0.9f, // Lower top-p for more deterministic responses
                };

                var message = new ChatHistory.Message(AuthorRole.User, userInput);
                var response = new StringBuilder();

                await foreach (var text in _session.ChatAsync(message, inferenceParams))
                {
                    response.Append(text);
                }

                return response.ToString();
            }
            catch (Exception ex)
            {
                Logging.Handler.Error("Classes.LLM.LLaMaService.GetResponseAsync", "userInput: " + userInput, ex.ToString());
                return "Something went wrong.";
            }
        }
    }

}
