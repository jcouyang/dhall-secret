module Dhall.Secret.IO where
import           Control.Lens       (set)
import qualified Data.Text          as T
import           Data.Version       (showVersion)
import           Data.Void          (Void, vacuous)
import           Dhall              (InputSettings, defaultInputSettings,
                                     evaluateSettings, inputExprWithSettings,
                                     substitutions)
import           Dhall.Core         (Directory (Directory), Expr (..),
                                     File (File), Import (Import),
                                     ImportHashed (ImportHashed),
                                     ImportMode (Code), ImportType (Remote),
                                     Scheme (HTTPS), URL (URL), freeIn,
                                     makeBinding, normalize, pretty)
import           Dhall.Freeze       (Intent (Secure), Scope (OnlyRemoteImports),
                                     freezeExpression)
import           Dhall.Import       (load)
import qualified Dhall.Map
import           Dhall.Secret.Type  (secretTypes)
import           Dhall.Src          (Src)
import qualified Paths_dhall_secret as P

version :: String
version = showVersion P.version

inputsetting :: InputSettings
inputsetting = set (evaluateSettings . substitutions ) (Dhall.Map.fromList ([("dhall-secret", secretTypes)])) defaultInputSettings

defineVar :: Expr Src Void -> Expr Src Import
defineVar = Let (makeBinding "dhall-secret" (Embed (Import (ImportHashed Nothing (Remote (URL HTTPS "raw.githubusercontent.com" (File (Directory $ reverse ["jcouyang", "dhall-secret", tag]) "Type.dhall") Nothing Nothing))) Code))) . vacuous
  where
    tag = if version == "0.1.0.0" then "master" else "v" <> T.pack version

addLetbinding :: Expr Src Void ->  IO (Expr Src Import)
addLetbinding x
  | freeIn "dhall-secret" x =  freezeExpression "." OnlyRemoteImports Secure $ defineVar x
  | otherwise = pure $ vacuous $ normalize x

parseExpr :: T.Text -> IO (Expr Src Void)
parseExpr text = inputExprWithSettings inputsetting text >>= addLetbinding >>= load

prettyExpr :: Expr Src Void -> IO T.Text
prettyExpr =  fmap pretty . addLetbinding
