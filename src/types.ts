export interface MalTokenResponse {
  token_type: string;
  expires_in: number;
  access_token: string;
  refresh_token: string;
}

export interface MalError {
  error: string;
  message?: string;
}

export interface AnimeSearchResult {
  data: Array<{
    node: {
      id: number;
      title: string;
      main_picture?: {
        medium: string;
        large: string;
      };
    };
  }>;
  paging: {
    next?: string;
    previous?: string;
  };
}
