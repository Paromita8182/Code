import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler



# We are importing the model, scaler and shift values (log transformation).
# However in the original project where the model was trained, the dataframes were scaled before any feature selection WHEREAS
# Our model was trained on the final set of features. Which means the scaler will have missing features and thus will not work. 
# Thus we will add the "missing features" while scaling and then remove these features when we pass it to our model
# For these extra features we will be generating dummy values since anyway they will be removed before any prediction.


class URLPrediction:
    
    def __init__(self):
        # Load pre-trained model, scaler, and shift value
        self.model = joblib.load('phishing_model.pkl')
        self.scaler = joblib.load('scaler.pkl')
        self.shift_value = joblib.load('shift_value.pkl')

        # Lists of features
        self.original_features_list = ['length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 
                                       'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 
                                       'nb_com', 'nb_dslash', 'http_in_path', 'ratio_digits_url', 'ratio_digits_host', 'nb_subdomains', 'nb_redirection', 'nb_external_redirection', 
                                       'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 'longest_word_host', 
                                       'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints', 'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 
                                       'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors', 'links_in_tags', 
                                       'ratio_intMedia', 'ratio_extMedia', 'safe_anchor', 'domain_registration_length', 'domain_age', 'web_traffic', 'page_rank']
        
        self.model_features_list = ['length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_qm', 'nb_and', 'nb_eq', 'nb_underscore', 'nb_slash', 'nb_www', 'nb_com', 
                                    'ratio_digits_url', 'ratio_digits_host', 'char_repeat', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 
                                    'longest_word_host', 'longest_word_path', 'phish_hints', 'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'nb_extCSS', 
                                    'ratio_extRedirection', 'ratio_extErrors', 'links_in_tags', 'ratio_intMedia', 'ratio_extMedia', 'safe_anchor', 'domain_registration_length', 
                                    'domain_age', 'web_traffic', 'page_rank', 'ip', 'https_token', 'prefix_suffix', 'external_favicon', 'empty_title', 'domain_in_title', 
                                    'domain_with_copyright', 'google_index']


    # Converting this dictionary to a Pandas dataframe always creates a "Unnamed: 0" column. So this function drops that column.
    def remove_col_unnamed(self, df):
        if "Unnamed: 0" in df.columns:
            df = df.drop(columns=["Unnamed: 0"])
        return df

    def compare_lists(self, list1, list2):
        # print(f"Comparing list1: {list1}")
        # print(f"Comparing list2: {list2}")
        missing_in_list2 = list(set(list1) - set(list2))  # Present in list1 but not in list2
        missing_in_list1 = list(set(list2) - set(list1))  # Present in list2 but not in list1

        return missing_in_list2, missing_in_list1

    def create_continuous_df(self, features_to_remove, features_to_add, df):
        continuous_df = df.drop(features_to_remove, axis=1, errors='ignore')
        for col in features_to_add:
            continuous_df[col] = -1
        return continuous_df

    def create_categorical_df(self, removed_features, df):
        categorical_df = df[removed_features]
        return categorical_df

    def transform_scale_data(self, continuous_df):
        # print(f"Original features list: {self.original_features_list}")
        # print(f"Continuous dataframe columns before transformation: {continuous_df.columns.tolist()}")
        
        missing_in_list2, missing_in_list1 = self.compare_lists(self.original_features_list, continuous_df.columns.tolist())
        
        if missing_in_list2 or missing_in_list1:
            # print(f"Missing in continuous dataframe: {missing_in_list2}")
            # print(f"Extra in continuous dataframe: {missing_in_list1}")
            return None

        continuous_df = continuous_df[self.original_features_list]
        shifted_df = continuous_df + self.shift_value
        transformed_df = np.log1p(shifted_df)
        # print(f"Columns after transformation: {transformed_df.columns.tolist()}")
        
        scaled_features = self.scaler.transform(transformed_df)
        scaled_df = pd.DataFrame(scaled_features, columns=transformed_df.columns)
        return scaled_df


    def final_df(self, scaled_df, categorical_df):
        final_df = pd.concat([scaled_df, categorical_df], axis=1)
        final_df = final_df[self.model_features_list]
        return final_df

    def predict(self, df):
        df = self.remove_col_unnamed(df)
        add_features, remove_features = self.compare_lists(self.original_features_list, df.columns.tolist())
        
        # Create separate dataframes for continuous and categorical features
        continuous_df = self.create_continuous_df(remove_features, add_features, df)
        categorical_df = self.create_categorical_df(remove_features, df)

        # Scale the continuous features
        scaled_df = self.transform_scale_data(continuous_df)
        if scaled_df is None:
            return "Error: Features mismatch!"

        # Combine the scaled continuous features with categorical features
        final_df = self.final_df(scaled_df, categorical_df)


        # Make the prediction using the model
        prediction = self.model.predict(final_df)
        if prediction == 1:
            return 1
        elif prediction == 0:
            return 0
        else:
            return None



# Example usage
if __name__ == "__main__":
    prediction_df = pd.read_csv("prediction_df.csv")    #Replace with actual dataframe of url in question. This is a dummy one.
    url_predictor = URLPrediction()
    prediction = url_predictor.predict(prediction_df)
    if prediction == 1:
        print("URL is Phishing!")
    elif prediction == 0:
        print("URL is Benign!")
    else:
        print("Error in prediction")
