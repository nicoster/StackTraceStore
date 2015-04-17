#ifdef STACKTRACESTORE_EXPORTS
#define STACKTRACESTORE_API __declspec(dllexport) 
#else
#define STACKTRACESTORE_API
#endif STACKTRACESTORE_EXPORTS


STACKTRACESTORE_API bool StoreStackBackTrace();
STACKTRACESTORE_API bool MonitorAPI(void* api);