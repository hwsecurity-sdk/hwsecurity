using System;
using Android.App;
using Android.Runtime;
using DE.Cotech.HW;

namespace HwsecurityWebViewSampleApp
{
#if DEBUG
    [Application(Debuggable = true)]
#else
    [Application(Debuggable = false)]
#endif
    public class TestApplication : Application
    {
        public TestApplication(IntPtr javaReference, JniHandleOwnership transfer) : base(javaReference, transfer)
        {
        }

        public TestApplication() { }

        public override void OnCreate()
        {
            base.OnCreate();

            SecurityKeyManager securityKeyManager = SecurityKeyManager.Instance;
            SecurityKeyManagerConfig config = new SecurityKeyManagerConfig.Builder().
                SetEnableDebugLogging(BuildConfig.Debug).
                Build();
            securityKeyManager.Init(this, config);
        }
    }
}
