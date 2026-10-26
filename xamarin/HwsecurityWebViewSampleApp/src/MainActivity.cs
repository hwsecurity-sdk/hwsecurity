using System;
using Android.App;
using Android.Graphics;
using Android.OS;
using Android.Runtime;
using Android.Support.Design.Widget;
using Android.Views;
using Android.Webkit;
using AndroidX.AppCompat.App;
using DE.Cotech.HW.Fido2;

namespace HwsecurityWebViewSampleApp
{
    [Activity(Label = "@string/app_name", Theme = "@style/AppTheme.NoActionBar", MainLauncher = true)]
    public class MainActivity : AppCompatActivity
    {
        internal class HwsecurityWebViewClient : WebViewClient
        {
            WebViewWebauthnBridge _webViewWebauthnBridge;

            public HwsecurityWebViewClient(WebViewWebauthnBridge webViewWebauthnBridge) : base()
            {
                _webViewWebauthnBridge = webViewWebauthnBridge;
            }

            public override WebResourceResponse ShouldInterceptRequest(WebView view, IWebResourceRequest request)
            {
                _webViewWebauthnBridge.DelegateShouldInterceptRequest(view, request);
                return base.ShouldInterceptRequest(view, request);
            }

            public override void OnPageStarted(WebView view, string url, Bitmap favicon)
            {
                base.OnPageStarted(view, url, favicon);
                _webViewWebauthnBridge.DelegateOnPageStarted(view, url, favicon);
            }
        }

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            Xamarin.Essentials.Platform.Init(this, savedInstanceState);
            SetContentView(Resource.Layout.activity_main);

            AndroidX.AppCompat.Widget.Toolbar toolbar = FindViewById<AndroidX.AppCompat.Widget.Toolbar>(Resource.Id.toolbar);
            SetSupportActionBar(toolbar);

            FloatingActionButton fab = FindViewById<FloatingActionButton>(Resource.Id.fab);
            fab.Click += FabOnClick;

            WebView webView = FindViewById<WebView>(Resource.Id.webview);
            webView.Settings.JavaScriptEnabled = true;

            WebViewWebauthnBridge webViewWebauthnBridge = WebViewWebauthnBridge.CreateInstanceForWebView(this, webView);
            webView.SetWebViewClient(new HwsecurityWebViewClient(webViewWebauthnBridge));

            webView.LoadUrl("https://webauthn.hwsecurity.dev");
        }

        public override bool OnCreateOptionsMenu(IMenu menu)
        {
            MenuInflater.Inflate(Resource.Menu.menu_main, menu);
            return true;
        }

        public override bool OnOptionsItemSelected(IMenuItem item)
        {
            int id = item.ItemId;
            if (id == Resource.Id.action_settings)
            {
                return true;
            }

            return base.OnOptionsItemSelected(item);
        }

        private void FabOnClick(object sender, EventArgs eventArgs)
        {
            View view = (View) sender;
            Snackbar.Make(view, "Replace with your own action", Snackbar.LengthLong)
                .SetAction("Action", (Android.Views.View.IOnClickListener)null).Show();
        }
        public override void OnRequestPermissionsResult(int requestCode, string[] permissions, [GeneratedEnum] Android.Content.PM.Permission[] grantResults)
        {
            Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode, permissions, grantResults);

            base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        }
	}
}

